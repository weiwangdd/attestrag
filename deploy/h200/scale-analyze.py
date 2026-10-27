"""host: summarize scale-<cfg>-<model>.json and bench-scale-<cfg>-<model>-<ds>.json into one table with CVM/plain ratios."""
import json, os, sys
models = ["1.5b", "7b", "14b", "80b"]
def load(path):
    try: return json.load(open(path))
    except Exception: return None
rows = []
for m in models:
    r = {"model": m}
    for cfg in ("cvm", "plain"):
        mb = load(f"scale-{cfg}-{m}.json")
        if mb:
            r[f"{cfg}_prefill"] = mb["c1"]["prefill_tps_median"]; r[f"{cfg}_decode"] = mb["c1"]["decode_tps_median"]
            r[f"{cfg}_prefill4"] = mb["c4"]["agg_prefill_tps"]; r[f"{cfg}_decode4"] = mb["c4"]["agg_gen_tps"]; r[f"{cfg}_wall"] = mb["c1"]["req_wall_median"]
        for ds in ("en_refine", "zh_refine"):
            b = load(f"bench-scale-{cfg}-{m}-{ds}.json")
            if b:
                s = b["summary"]; r[f"{cfg}_{ds[:2]}_p50"] = s["ask_latency"]["p50"]
                sw = {x["concurrency"]: x for x in b.get("sweep", [])} if isinstance(b.get("sweep"), list) else {}
                if sw: r[f"{cfg}_{ds[:2]}_q8"] = sw.get(8, {}).get("qps")
    rows.append(r)
def f(v, d=1): return "-" if v is None else f"{v:.{d}f}"
def ratio(a, b, inv=False):
    if a is None or b is None or b == 0: return "-"
    x = (a / b) if not inv else (b / a)
    return f"{x:.2f}x"
print("model | prefill tok/s cvm/plain (ratio) | decode tok/s c1 cvm/plain (ratio) | decode agg c4 cvm/plain | ask p50 en cvm/plain (overhead) | ask p50 zh cvm/plain (overhead) | 8-user q/s en cvm/plain | zh")
for r in rows:
    g = r.get
    def ov(a, b): return "-" if a is None or b is None else f"+{(a/b-1)*100:.0f}%"
    print(f"{r['model']} | {f(g('cvm_prefill'),0)}/{f(g('plain_prefill'),0)} ({ratio(g('cvm_prefill'), g('plain_prefill'))}) | "
          f"{f(g('cvm_decode'),0)}/{f(g('plain_decode'),0)} ({ratio(g('cvm_decode'), g('plain_decode'))}) | {f(g('cvm_decode4'),0)}/{f(g('plain_decode4'),0)} | "
          f"{f(g('cvm_en_p50'),2)}/{f(g('plain_en_p50'),2)} ({ov(g('cvm_en_p50'), g('plain_en_p50'))}) | {f(g('cvm_zh_p50'),2)}/{f(g('plain_zh_p50'),2)} ({ov(g('cvm_zh_p50'), g('plain_zh_p50'))}) | "
          f"{f(g('cvm_en_q8'),2)}/{f(g('plain_en_q8'),2)} | {f(g('cvm_zh_q8'),2)}/{f(g('plain_zh_q8'),2)}")
