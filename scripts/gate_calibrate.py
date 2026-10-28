"""Pick the relevance-gate threshold from benchmark runs that recorded top retrieval scores.

    python scripts/gate_calibrate.py bench-zh.json bench-en.json [--max-false-rejection 0.02]

For every candidate threshold t over the observed top scores: rejection on held-out questions
(whose positives were never ingested) and false rejection on answerable ones if the node refused
whenever top_score < t. Prints the trade-off table and the largest t that keeps false rejection
within the bound, per file and pooled. The score scale is the embedder's (cosine), so recalibrate
when the embedder changes.
"""

import argparse
import json
import sys


def load(path):
    rows = [r for r in json.load(open(path))["results"] if "top_score" in r and r.get("top_score") is not None]
    return [(r["top_score"], r["held_out"], r.get("correct", False)) for r in rows]


def table(rows, max_fr):
    scores = sorted({s for s, _, _ in rows})
    held = [s for s, h, _ in rows if h]
    ans = [s for s, h, _ in rows if not h]
    best = None
    out = []
    for t in scores:
        rej = sum(1 for s in held if s < t) / max(1, len(held))
        fr = sum(1 for s in ans if s < t) / max(1, len(ans))
        out.append((t, rej, fr))
        if fr <= max_fr:
            best = (t, rej, fr)
    return out, best, (min(held) if held else None, max(held) if held else None), (min(ans) if ans else None, max(ans) if ans else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--max-false-rejection", type=float, default=0.02)
    a = ap.parse_args()
    pooled = []
    for f in a.files:
        rows = load(f)
        if not rows:
            print(f"{f}: no top_score in results (benchmark predates the gate)"); continue
        pooled += rows
        out, best, hr, ar = table(rows, a.max_false_rejection)
        print(f"== {f}: {len(rows)} questions; held-out top scores {hr[0]:.3f}..{hr[1]:.3f}, answerable {ar[0]:.3f}..{ar[1]:.3f}")
        for t, rej, fr in out[::max(1, len(out) // 12)]:
            print(f"   t >= {t:.3f}: held-out rejection {rej:.2f}  false rejection {fr:.3f}")
        print(f"   best with false rejection <= {a.max_false_rejection}: " + (f"t = {best[0]:.3f} -> rejection {best[1]:.2f}, false rejection {best[2]:.3f}" if best else "none"))
    if len(a.files) > 1 and pooled:
        _, best, _, _ = table(pooled, a.max_false_rejection)
        print("== pooled: " + (f"t = {best[0]:.3f} -> rejection {best[1]:.2f}, false rejection {best[2]:.3f}" if best else "none"))


if __name__ == "__main__":
    sys.exit(main())
