#!/usr/bin/env python3
"""Realistic RAG benchmark against a live AttestRAG node, using the RGB dataset.

RGB (Chen et al., "Benchmarking Large Language Models in Retrieval-Augmented
Generation", AAAI 2024, https://github.com/chen700564/RGB, CC BY-NC-SA 4.0) has
300 English and 300 Chinese questions; each comes with positive passages (contain
the answer), negative passages (same topic, no answer) and answer aliases.

What this script measures, end to end through the attested client path
(attestation -> policy -> encrypted upload -> encrypted question -> sealed answer):

  ingest      all positive + negative passages of the sampled questions, one
              document per question (passages shuffled), through /ingest
  retrieval   hit@k: does any of the k retrieved chunks overlap a positive passage
  answer      RGB-style exact match: every answer part has an alias in the reply
  rejection   for a held-out fraction, only the negatives are ingested; the node
              should say the context is insufficient (negative rejection)
  latency     per-stage client-side timings: connect (attest+verify), ingest, ask
  concurrency optional sweep: N users, each with its own attested session, asking
              questions outside the main sample (unseen prompts; llama-server
              would otherwise serve repeated prompts from its KV cache)

    python scripts/rag_bench.py --node http://127.0.0.1:8081 --policy policy.json \
        --dataset zh_refine --limit 100 --holdout 0.2 --sweep 1,2,4 --out bench.json
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import random
import re
import statistics
import sys
import time
import urllib.request
from pathlib import Path

from attestrag.attest import CompositeVerifier, Platform
from attestrag.attest.nvidia import NvidiaVerifier
from attestrag.attest.snp import KdsClient, SnpVerifier
from attestrag.policy import Policy
from attestrag.sdk import AttestRAGClient
from attestrag.sdk.http import HttpNodeTransport

RGB_RAW = "https://raw.githubusercontent.com/chen700564/RGB/master/data/{name}.json"
RGB_ROWS = {"en_refine": 300, "zh_refine": 300, "en": 300, "zh": 300, "en_int": 100, "zh_int": 100}

REJECT_RE = re.compile(
    r"insufficient|not provide|does not (contain|mention|include|specify|state)|doesn't (contain|mention)|"
    r"no (information|mention)|cannot (answer|determine|be determined)|can't (answer|determine)|unable to|"
    r"not enough information|not mentioned|not specified|not available in|no relevant|"
    r"无法|没有提|未提|不足|没有相关|没有找到|不包含|无相关|未找到|未包含|没有说明|无法确定|没有涉及",
    re.I,
)


# --- dataset ------------------------------------------------------------------
def load_rgb(name: str, cache: Path) -> list[dict]:
    cache.mkdir(parents=True, exist_ok=True)
    f = cache / f"{name}.json"
    if not f.exists():
        print(f"downloading {name} ...", file=sys.stderr)
        urllib.request.urlretrieve(RGB_RAW.format(name=name), f)
    rows = [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    if name in RGB_ROWS and len(rows) != RGB_ROWS[name]:
        raise SystemExit(f"{f}: expected {RGB_ROWS[name]} rows, got {len(rows)}")
    return rows


def positives(row: dict) -> list[str]:
    p = row["positive"]
    return p if not p or isinstance(p[0], str) else [x for sub in p for x in sub]


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def answer_ok(answer, text: str) -> bool:
    """RGB check: each answer part is a string or a list of aliases; all parts must appear."""
    t = text.lower()
    for part in answer:
        aliases = part if isinstance(part, list) else [part]
        if not any(str(a).lower() in t for a in aliases):
            return False
    return True


def overlaps(hit: str, passages: list[str], window: int = 120) -> bool:
    """Chunks rarely coincide with passages; count a hit if it shares a window-long substring."""
    h = norm(hit)
    for p in passages:
        p = norm(p)
        if len(p) <= window:
            if p in h:
                return True
            continue
        for i in range(0, len(p) - window + 1, window // 2):
            if p[i:i + window] in h:
                return True
    return False


# --- client -------------------------------------------------------------------
def make_client(args) -> tuple[AttestRAGClient, float]:
    verifier = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(KdsClient(args.kds_cache), product=args.product),
                                   Platform.NVIDIA_CC: nvidia_verifier(args)})
    if args.insecure_mock:
        from attestrag.attest.mock import insecure_baseline_verifier
        print("WARNING: --insecure-mock: accepting evidence from the public mock vendor; nothing is protected", file=sys.stderr)
        verifier = CompositeVerifier({**verifier.verifiers, Platform.MOCK_CPU: insecure_baseline_verifier()})
    client = AttestRAGClient(HttpNodeTransport(args.node, timeout=args.timeout), verifier,
                             Policy.from_json(Path(args.policy).read_text()))
    t = time.perf_counter()
    client.connect()  # raises NodeUntrusted: nothing is sent to an unverified node
    return client, time.perf_counter() - t


def pct(xs: list[float], p: float) -> float:
    if not xs:
        return float("nan")
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def lat(xs: list[float]) -> dict:
    return {"n": len(xs), "mean": statistics.fmean(xs) if xs else None, "p50": pct(xs, 50), "p90": pct(xs, 90),
            "max": max(xs) if xs else None}


# --- phases -------------------------------------------------------------------
def ingest(client: AttestRAGClient, rows: list[dict], holdout: set[int], tag: str, rng: random.Random) -> dict:
    per_doc, chunks, chars = [], 0, 0
    t0 = time.perf_counter()
    for i, row in enumerate(rows):
        passages = list(row["negative"]) + ([] if row["id"] in holdout else positives(row))
        rng.shuffle(passages)
        text = "\n\n".join(norm(p) for p in passages)
        chars += len(text)
        t = time.perf_counter()
        n = client.upload(f"rgb-{tag}-q{row['id']}", text.encode(), "text/plain")
        per_doc.append(time.perf_counter() - t)
        chunks += n
        if (i + 1) % 10 == 0 or i + 1 == len(rows):
            print(f"  ingest {i + 1}/{len(rows)} docs, {chunks} chunks, {time.perf_counter() - t0:.0f}s", file=sys.stderr)
    total = time.perf_counter() - t0
    return {"docs": len(rows), "chunks": chunks, "chars": chars, "seconds": total,
            "chunks_per_s": chunks / total if total else None, "doc_latency": lat(per_doc)}


def ask_one(client: AttestRAGClient, row: dict, k: int, held_out: bool) -> dict:
    t = time.perf_counter()
    try:
        res = client.ask(row["query"], k)
    except Exception as e:  # noqa: BLE001 - record and continue
        return {"id": row["id"], "held_out": held_out, "error": str(e), "latency": time.perf_counter() - t}
    dt = time.perf_counter() - t
    text = res["answer"]["text"]
    pos = positives(row)
    hits = [overlaps(h["text"], pos) for h in res["hits"]]
    return {
        "id": row["id"], "query": row["query"], "held_out": held_out, "latency": dt,
        "hit_at_k": any(hits), "hit_rank": (hits.index(True) + 1) if any(hits) else None,
        "positive_hits": sum(hits), "k": len(hits),
        "correct": answer_ok(row["answer"], text), "rejected": bool(REJECT_RE.search(text)),
        "cited": len(res["answer"]["citations"]), "answer": text[:400],
    }


def summarize(results: list[dict]) -> dict:
    ok = [r for r in results if "error" not in r]
    served = [r for r in ok if not r["held_out"]]
    held = [r for r in ok if r["held_out"]]

    def rate(xs, key):
        return (sum(1 for x in xs if x[key]) / len(xs)) if xs else None

    return {
        "questions": len(results), "errors": len(results) - len(ok),
        "answerable": {
            "n": len(served), "hit_at_k": rate(served, "hit_at_k"), "answer_acc": rate(served, "correct"),
            "answer_acc_given_hit": rate([r for r in served if r["hit_at_k"]], "correct"),
            "false_rejection": rate(served, "rejected"),
            "mean_positive_chunks": statistics.fmean(r["positive_hits"] for r in served) if served else None,
        },
        "held_out": {
            "n": len(held), "rejection": rate(held, "rejected"), "answered_anyway_correct": rate(held, "correct"),
            "hit_at_k_should_be_0": rate(held, "hit_at_k"),
        },
        "ask_latency": lat([r["latency"] for r in ok]),
    }


def sweep(args, pool: list[dict], holdout: set[int], levels: list[int], n_per_level: int) -> list[dict]:
    """Each level asks n fresh questions (never asked before: llama-server caches prompt prefixes)."""
    out = []
    for i, c in enumerate(levels):
        qs = [pool[(i * n_per_level + j) % len(pool)] for j in range(n_per_level)]
        clients, connects = [], []
        for _ in range(c):
            cl, dt = make_client(args)
            clients.append(cl)
            connects.append(dt)
        t0 = time.perf_counter()
        with cf.ThreadPoolExecutor(max_workers=c) as ex:
            futs = [ex.submit(ask_one, clients[i % c], q, args.k, q["id"] in holdout) for i, q in enumerate(qs)]
            res = [f.result() for f in futs]
        wall = time.perf_counter() - t0
        lats = [r["latency"] for r in res if "error" not in r]
        row = {"concurrency": c, "requests": len(qs), "errors": sum("error" in r for r in res), "wall_s": wall,
               "qps": len(qs) / wall, "latency": lat(lats), "connect": lat(connects)}
        print(f"  concurrency {c}: {row['qps']:.2f} q/s, p50 {row['latency']['p50']:.2f}s, "
              f"p90 {row['latency']['p90']:.2f}s, errors {row['errors']}", file=sys.stderr)
        out.append(row)
    return out


def nvidia_verifier(args) -> NvidiaVerifier:
    if not getattr(args, "gpu_rim", False):
        return NvidiaVerifier()
    from attestrag.attest.nvidia_rim import OcspClient, RimClient
    base = Path(args.nvidia_cache) if args.nvidia_cache else Path.home() / ".cache" / "attestrag" / "nvidia"
    return NvidiaVerifier(rim=RimClient(base / "rim"), ocsp=OcspClient(cache_dir=base / "ocsp"))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--product", choices=["Milan", "Genoa", "Turin"])
    ap.add_argument("--kds-cache")
    ap.add_argument("--gpu-rim", action="store_true",
                    help="also check GPU evidence against NVIDIA's reference manifests (RIM service) and OCSP; cached in --nvidia-cache")
    ap.add_argument("--nvidia-cache", help="cache dir for RIMs and OCSP responses (default ~/.cache/attestrag/nvidia)")
    ap.add_argument("--insecure-mock", action="store_true",
                    help="also trust the public insecure-baseline mock vendor (unprotected baseline only; proves nothing)")
    ap.add_argument("--dataset", default="zh_refine", choices=sorted(RGB_ROWS))
    ap.add_argument("--data-dir", default=str(Path.home() / ".cache" / "attestrag" / "rgb"))
    ap.add_argument("--limit", type=int, default=100, help="questions to sample (0 = all)")
    ap.add_argument("--holdout", type=float, default=0.2, help="fraction whose positives are NOT ingested")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("-k", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--skip-ingest", action="store_true", help="corpus already on the node (same seed/limit)")
    ap.add_argument("--skip-questions", action="store_true")
    ap.add_argument("--sweep", help="comma-separated concurrency levels, e.g. 1,2,4")
    ap.add_argument("--sweep-n", type=int, default=16, help="requests per concurrency level")
    ap.add_argument("--out", help="write full results JSON here")
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    all_rows = load_rgb(args.dataset, Path(args.data_dir))
    rows = rng.sample(all_rows, args.limit) if args.limit and args.limit < len(all_rows) else all_rows
    used = {r["id"] for r in rows}
    sweep_pool = [r for r in all_rows if r["id"] not in used] or rows  # unseen questions, no prompt-cache hits
    holdout = {r["id"] for r in rng.sample(rows, int(round(args.holdout * len(rows))))}
    print(f"dataset {args.dataset}: {len(rows)} questions, {len(holdout)} held out, k={args.k}", file=sys.stderr)

    report = {"dataset": args.dataset, "limit": args.limit, "holdout": sorted(holdout), "k": args.k,
              "seed": args.seed, "node": args.node, "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    client, dt = make_client(args)
    c = client.claims.cpu
    print(f"node verified: measurement={c.measurement[:16]}... tcb={c.tcb} connect={dt:.3f}s", file=sys.stderr)
    report["connect_s"] = dt
    report["measurement"] = c.measurement

    if not args.skip_ingest:
        report["ingest"] = ingest(client, rows, holdout, args.dataset, random.Random(args.seed + 1))
        print(f"ingested {report['ingest']['chunks']} chunks in {report['ingest']['seconds']:.0f}s "
              f"({report['ingest']['chunks_per_s']:.1f} chunks/s)", file=sys.stderr)

    if not args.skip_questions:
        results = []
        t0 = time.perf_counter()
        for i, row in enumerate(rows):
            results.append(ask_one(client, row, args.k, row["id"] in holdout))
            if (i + 1) % 10 == 0 or i + 1 == len(rows):
                s = summarize(results)
                print(f"  ask {i + 1}/{len(rows)} {time.perf_counter() - t0:.0f}s  hit@k={s['answerable']['hit_at_k']} "
                      f"acc={s['answerable']['answer_acc']} rej={s['held_out']['rejection']}", file=sys.stderr)
        report["results"] = results
        report["summary"] = summarize(results)

    if args.sweep:
        report["sweep_pool"] = "unseen questions" if sweep_pool is not rows else "same questions (prompt cache!)"
        report["sweep"] = sweep(args, sweep_pool, holdout, [int(x) for x in args.sweep.split(",")], args.sweep_n)

    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1))
    print(json.dumps({k: v for k, v in report.items() if k not in ("results", "holdout")}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
