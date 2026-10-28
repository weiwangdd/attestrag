"""The AttestRAG node as an HTTP service. Runs INSIDE the SEV-SNP CVM (root, for configfs-tsm).

    sudo python -m attestrag.node_server --kbs http://10.0.2.2:8800 --data-dir /var/lib/attestrag

Boot: attest to the KBS (whose identity is pinned with --kbs-pubkey), receive each tenant's index
key with its committed version, open/create the encrypted indexes (refusing a rolled-back one), warm
the generator up. Then serve /attestation, /ingest, /query (see node.node_routes).
"""

from __future__ import annotations

import argparse
import sys

from .attest import AttestationError, CompositeAttester
from .attest.snp import SnpAttester
from .attest.nvidia import NvidiaAttester
from .attest.tdx import TdxAttester
from .embed import HashingEmbedder, OpenAIEmbedder
from .generate import OpenAICompatibleGenerator, StubGenerator
from .index import IndexRollback
from .kbs_client import HttpKBS, KBSClient, KeyReleaseDenied
from .node import AttestRAGNode, node_routes
from .transport import JsonServer


def _wait_http(url: str, timeout: float) -> None:
    import time
    import urllib.request
    deadline = time.time() + timeout
    while True:
        try:
            urllib.request.urlopen(url, timeout=5).read()
            return
        except Exception as e:  # noqa: BLE001
            if time.time() > deadline:
                print(f"[node] {url} not ready after {timeout:.0f}s: {e}", file=sys.stderr)
                sys.exit(4)
            time.sleep(2)


def _probe_gpus() -> list[int]:
    from .attest.nvidia import probe_cc_gpus
    return probe_cc_gpus()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.node_server")
    ap.add_argument("--listen", default="0.0.0.0:8080")
    ap.add_argument("--kbs", required=True, help="KBS base URL, e.g. http://10.0.2.2:8800")
    ap.add_argument("--data-dir", default="/var/lib/attestrag")
    ap.add_argument("--key-id", default="index-dek", help="KBS key id of the single default tenant")
    ap.add_argument("--tenant", action="append", default=[], metavar="ID",
                    help="serve this tenant (KBS key id; repeatable): one key, one sealed index, one client token each. "
                         "Default: the single tenant --key-id with the historical file names")
    ap.add_argument("--kbs-pubkey", metavar="HEX",
                    help="Ed25519 identity of the KBS (kbs_server --print-pubkey); releases not signed by it are refused. "
                         "Part of the measured configuration; without it a host in the middle can substitute the key")
    ap.add_argument("--llm", help="OpenAI-compatible /v1 endpoint for generation (default: extractive stub)")
    ap.add_argument("--model", default="local")
    ap.add_argument("--embed", help="OpenAI-compatible /v1 endpoint for embeddings (default: hashing embedder)")
    ap.add_argument("--embed-model", default="local")
    ap.add_argument("--embed-dim", type=int, default=512, help="hashing embedder dimension")
    ap.add_argument("--wait", type=float, default=120.0, help="seconds to wait for --llm/--embed/--qdrant-url to come up")
    ap.add_argument("--vector-store", choices=["sealed", "qdrant"], default="sealed",
                    help="sealed = in-memory index persisted as one AES-GCM blob; qdrant = Qdrant in the CVM (tmpfs storage, sealed snapshots)")
    ap.add_argument("--qdrant-url", default="http://127.0.0.1:6333")
    ap.add_argument("--qdrant-collection", default="attestrag")
    ap.add_argument("--gpu", action="append", default=[], metavar="INDEX|auto",
                    help="NVML index of a confidential-computing GPU whose attestation is bound into every report "
                         "(repeatable); 'auto' = every GPU that can produce an attestation report, none if there is no GPU")
    ap.add_argument("--min-score", type=float, default=0.0,
                    help="relevance gate: refuse (without calling the generator) when the best chunk scores below this; 0 = off")
    ap.add_argument("--judge", action="store_true",
                    help="relevance gate, stage 2: ask the generator YES/NO whether the context contains the answer before answering")
    ap.add_argument("--attester", choices=["snp", "tdx", "mock-insecure"], default="snp",
                    help="snp: SEV-SNP via configfs-tsm; tdx: Intel TDX quote via configfs-tsm; "
                         "mock-insecure: NO attestation (public mock vendor), for the unprotected baseline in a plain VM only")
    args = ap.parse_args(argv)

    gpus: list[NvidiaAttester] = []
    for g in args.gpu:
        gpus += [NvidiaAttester(i) for i in (_probe_gpus() if g == "auto" else [int(g)])]
    print(f"[node] GPU attesters: {[a.index for a in gpus] or 'none'}", file=sys.stderr)
    if args.attester == "mock-insecure":
        from .attest.mock import insecure_baseline_attester
        print("[node] WARNING: --attester mock-insecure: this node proves nothing (unprotected baseline)", file=sys.stderr)
        attester = CompositeAttester(insecure_baseline_attester(), gpus)
    elif args.attester == "tdx":
        attester = CompositeAttester(TdxAttester(), gpus)
    else:
        attester = CompositeAttester(SnpAttester(), gpus)
    for url in (args.llm, args.embed):
        if url:
            _wait_http(url.rstrip("/") + "/models", args.wait)
    gen = OpenAICompatibleGenerator(args.llm, model=args.model) if args.llm else StubGenerator()
    emb = OpenAIEmbedder(args.embed, model=args.embed_model) if args.embed else HashingEmbedder(args.embed_dim)
    print(f"[node] embedder={type(emb).__name__} dim={emb.dim} generator={type(gen).__name__}",
          file=sys.stderr, flush=True)
    tenants = args.tenant or None
    store_factory = None
    if args.vector_store == "qdrant":
        from .index.qdrant import QdrantStore
        _wait_http(args.qdrant_url.rstrip("/") + "/healthz", args.wait)
        # one collection per tenant; the single default tenant keeps the historical collection name
        store_factory = lambda t: QdrantStore(args.qdrant_url, args.qdrant_collection if not tenants else f"{args.qdrant_collection}-{t}", dim=emb.dim)  # noqa: E731
        print(f"[node] vector store=QdrantStore url={args.qdrant_url} collection={args.qdrant_collection}",
              file=sys.stderr, flush=True)
    kbs_pub = bytes.fromhex(args.kbs_pubkey) if args.kbs_pubkey else None
    if kbs_pub is None:
        print("[node] WARNING: no --kbs-pubkey: key releases are not authenticated (a host in the middle can substitute the key)",
              file=sys.stderr, flush=True)
    node = AttestRAGNode(attester, KBSClient(HttpKBS(args.kbs), attester, kbs_pubkey=kbs_pub), emb,
                         gen, args.data_dir, index_key_id=args.key_id, min_score=args.min_score, judge=args.judge,
                         tenants=tenants, store_factory=store_factory)
    if args.min_score > 0 or args.judge:
        print(f"[node] relevance gate: min_score={args.min_score} judge={args.judge}", file=sys.stderr, flush=True)
    try:
        node.start()
    except KeyReleaseDenied as e:
        print(f"[node] KBS refused to release: {e}", file=sys.stderr)
        sys.exit(3)
    except AttestationError as e:
        print(f"[node] KBS release rejected: {e}", file=sys.stderr)
        sys.exit(3)
    except IndexRollback as e:
        print(f"[node] REFUSING TO START: {e}", file=sys.stderr)
        sys.exit(5)
    for t in node.tenants.values():
        print(f"[node] tenant {t.id!r}: key released, index version {t.version} (committed {t.committed}), "
              f"{len(t.store)} chunks at {t.path}, client token {'required' if t.token else 'none (open tenant)'}",
              file=sys.stderr, flush=True)
    if args.llm:
        import time
        t0 = time.time()
        gen.warm_up()
        print(f"[node] generator warm-up {time.time() - t0:.1f}s (first request would otherwise pay for it)", file=sys.stderr, flush=True)
    host, port = args.listen.rsplit(":", 1)
    srv = JsonServer(node_routes(node), (host, int(port)))
    print(f"[node] listening on {srv.url}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
