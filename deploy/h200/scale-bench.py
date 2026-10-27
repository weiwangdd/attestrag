"""guest: token-throughput microbenchmark against llama-chat. Fixed ~1.5k-token prompt, 128 generated tokens,
concurrency 1 and 4; reports llama-server's own timings (prefill and decode tokens/s) and wall time."""
import json, sys, time, urllib.request, statistics, threading, uuid
URL = "http://127.0.0.1:8091/v1/chat/completions"
PARA = ("The attestation report of a confidential virtual machine is signed by the platform security processor "
        "and covers the launch measurement, the guest policy and sixty-four bytes of report data chosen by the guest. ")
PROMPT = PARA * 60 + "\n\nSummarize the text above in three sentences."
def one(tag):
    # unique prefix + cache_prompt off: otherwise llama-server reuses the cached prefix and prefill is not measured
    body = {"messages": [{"role": "user", "content": f"[request {uuid.uuid4()}]\n" + PROMPT}], "max_tokens": 128, "temperature": 0,
            "stream": False, "cache_prompt": False}
    t0 = time.time()
    r = urllib.request.urlopen(urllib.request.Request(URL, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}), timeout=600)
    d = json.loads(r.read()); t = d["timings"]
    return {"wall": time.time() - t0, "prompt_n": t["prompt_n"], "prompt_tps": t["prompt_per_second"], "gen_n": t["predicted_n"], "gen_tps": t["predicted_per_second"]}
out = {"model": sys.argv[1]}
for _ in range(2): one("warm")
for conc in (1, 4):
    res = []; lock = threading.Lock()
    def worker(n):
        for _ in range(n):
            x = one("t")
            with lock: res.append(x)
    t0 = time.time(); ths = [threading.Thread(target=worker, args=(8 // conc,)) for _ in range(conc)]
    [t.start() for t in ths]; [t.join() for t in ths]; wall = time.time() - t0
    out[f"c{conc}"] = {"n": len(res), "prompt_n": res[0]["prompt_n"], "prefill_tps_median": statistics.median(r["prompt_tps"] for r in res),
                       "decode_tps_median": statistics.median(r["gen_tps"] for r in res), "req_wall_median": statistics.median(r["wall"] for r in res),
                       "agg_gen_tps": sum(r["gen_n"] for r in res) / wall, "agg_prefill_tps": sum(r["prompt_n"] for r in res) / wall}
print(json.dumps(out))
