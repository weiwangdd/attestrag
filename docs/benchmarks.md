# RAG benchmark on the h200 CVM

Measured 2026-10-20 against the running node on h200 (SEV-SNP guest, 32 vCPUs, 16 GB,
CPU-only llama.cpp, GPU and 7B results from 2026-10-23 at the end: Qwen3-Embedding-0.6B Q8_0 + Qwen2.5-1.5B-Instruct Q4_K_M, Qdrant in tmpfs).
Everything goes through the attested client path: attestation + policy check, encrypted
upload, encrypted question, sealed answer. Script: `scripts/rag_bench.py`.

## Dataset

[RGB](https://github.com/chen700564/RGB) (Chen et al., *Benchmarking Large Language Models
in Retrieval-Augmented Generation*, AAAI 2024; CC BY-NC-SA 4.0). 300 English and 300
Chinese news questions (2022–2023). Each question has positive passages (contain the answer),
negative passages (same topic, no answer) and a list of answer aliases. We use the
`*_refine` splits (March 2024 corrections).

Why this one: it is a corpus-plus-questions benchmark small enough to ingest into an 8–32
vCPU CVM in minutes, it is bilingual, and it separates retrieval quality (did a positive
passage come back) from generation quality (is the answer in the reply) and from
*negative rejection* (does the model admit the context is insufficient). Alternatives
considered: CRUD-RAG (Chinese, 80k-document corpus, ~3 h to index), CRAG (KDD Cup 2024,
HTML pages + mock APIs, CC BY-NC), RAGBench (pre-retrieved contexts, judges the generator
only), BEIR/MTEB (retrieval only).

## Method

For a seeded sample of 100 questions per language:

1. **ingest** – one document per question holding its positive + negative passages,
   shuffled (median 24 passages), uploaded through `/ingest`. For a held-out 20 % the
   positives are omitted, so the corpus has on-topic noise but no answer.
2. **ask** – each question once, `k=4`, through `/query`.
   *hit@4*: a retrieved chunk shares a 120-character window with a positive passage.
   *answer accuracy*: RGB's check, every answer part has an alias in the reply
   (case-insensitive substring).
   *rejection*: the reply contains an "insufficient context" phrase (regex, both languages).
3. **concurrency sweep** – N clients, each with its own attested session, 16 requests
   per level, questions never asked before (llama-server caches prompt prefixes, so
   repeating questions would measure its KV cache).

All timings are client side on the host, so they include the slirp hop into the guest.

## Results

### Accuracy (100 questions per language, 80 answerable + 20 held out)

| | zh_refine | en_refine |
|---|---|---|
| corpus ingested | 100 docs, 814 chunks, 470 k chars | 100 docs, 3762 chunks, 2.1 M chars |
| hit@4 (a positive passage among the 4 chunks) | 1.00 | 1.00 |
| positive chunks among the 4 (mean) | 3.2 | 3.1 |
| answer accuracy (RGB alias match) | 0.94 | 0.96 |
| false rejection on answerable questions | 0.00 | 0.00 |
| held out: rejection ("context insufficient") | 0.05 | 0.05 |
| held out: answered correctly from memory | 0.00 | 0.05 |

Retrieval is not the problem: Qwen3-Embedding-0.6B over 800-character chunks puts a
positive passage in the top 4 for every question, with ~3 of the 4 chunks positive, in a
corpus where 2/3 of the passages are on-topic noise. The remaining answer errors are the
1.5B generator picking the wrong fact out of the context (e.g. the deported player instead
of the champion for "2022 Australian Open men's winner") or alias mismatches.

**Negative rejection is the weak spot.** When the answer is not in the corpus the model
almost never says so: it answers from pretraining or fabricates (wrong Olympic pairs
champion, wrong Nobel laureates, "Shinzo Abe died on [chunk id]"). The system prompt's
"if the context is insufficient, say so" is not enough for a 1.5B model; the RGB paper
reports the same failure even for ChatGPT. A production node needs a larger model, an
explicit relevance gate (drop chunks below a similarity threshold, refuse when none
remain) or a verifier pass. 20 % of held-out English questions still got a positive chunk
because RGB passages are shared between questions.

### Latency (client side, one user at a time)

| | zh_refine | en_refine |
|---|---|---|
| connect (SNP report + KDS-cached VCEK verify + policy) | 0.03 s | 0.03 s |
| ingest, per document (median 24 passages) | p50 4.5 s, p90 5.9 s | p50 6.1 s, p90 8.6 s |
| ingest throughput | 1.8 chunks/s | 6.2 chunks/s |
| ask (embed + Qdrant + generate), k=4 | p50 3.2 s, p90 3.7 s, max 5.9 s | p50 1.4 s, p90 1.7 s, max 2.1 s |

Chinese is slower because the same 800 characters are ~3x more tokens for Qwen: the
chat prompt is ~2000 tokens (prompt processing ~700 tok/s on 32 vCPUs) against ~700 for
English. Ingest cost is embedding plus the whole-collection sealed snapshot after every
document; per-document time grows with the collection (zh 4.5 s at 800 chunks, en 6.1 s
at 3800 chunks). Compared to the first configuration (8 vCPUs, 2 embedding threads,
6 chat threads) ingest went from 0.31 to 1.8 chunks/s and a Chinese answer from 10.3 s
to 3.2 s, which is why the CVM now has 32 vCPUs and 32 threads per llama-server.

### Concurrency (English, 16 unseen questions per level, one attested session per user)

| users | en: q/s | en: p50 / p90 | zh: q/s | zh: p50 / p90 | errors |
|---|---|---|---|---|---|
| 1 | 0.60 | 1.4 s / 2.7 s | 0.36 | 3.1 s / 3.5 s | 0 |
| 2 | 0.21 | 8.9 s / 16.4 s | 0.18 | 12.5 s / 16.7 s | 0 |
| 4 | 0.23 | 17.4 s / 25.6 s | 0.17 | 17.6 s / 35.8 s | 0 |
| 8 | 0.29 | 26.5 s / 39.5 s | 0.24 | 34.3 s / 47.6 s | 0 |

Session setup is not the cost: a new attested session (SNP report through configfs-tsm,
signature + chain check with the cached VCEK, policy evaluation) takes 10–30 ms, so
per-user attestation is free compared with one answer.

The CPU inference is. **Throughput drops 3x as soon as two users overlap** and never
recovers: llama-server b11753 runs 4 slots on a unified KV cache, so two prompts are
processed interleaved while the embedding server (32 threads) and the chat server
(32 threads) also run at the same time on 32 vCPUs. Oversubscribed OpenMP threads
spin instead of computing. With the first build of this image (`-c 4096`) the same
sweep failed outright for 2+ users ("failed to find free space in the KV cache", 25–100 %
errors); `-c 16384 -np 4` removed the errors but not the slowdown.

What to change next, in order of expected effect:

1. Serialize generation (`-np 1`) or give the chat server a request queue in the node,
   so throughput stays at the single-user 0.6 q/s and extra users only wait.
2. Split threads so embedding + generation together never exceed the vCPU count
   (e.g. 8 + 24), or embed queries on the chat server's idle time.
3. GPU CC (step 4 of the plan): prompt processing at 700 tok/s is the whole budget;
   an H200 in CC mode does the same in milliseconds.

### GPU confidential computing (step 4, measured 2026-10-23)

Same image family, same corpus already sealed on the data disk (`--skip-ingest`), same
100 questions and sweep questions, but H200 NVL GPU3 of the host passed through to the
CVM in NVIDIA confidential-computing mode (`deploy/h200/gpu3-cc-on.sh`, `GPU=0000:44:00.0`)
and both llama-servers on the CUDA build with every layer offloaded. The node now sends
GPU evidence too, and the policy requires it (`require_gpu`, the composite GPU
measurement pinned), so "connect" below includes verifying the NVIDIA transcript and
its certificate chain as well as the SNP report.

| | zh_refine | en_refine |
|---|---|---|
| connect (SNP + GPU evidence, policy) | 0.07 s | 0.06 s |
| answer accuracy (RGB alias match) | 0.95 | 0.975 |
| hit@4 / false rejection / held-out rejection | 1.00 / 0.00 / 0.05 | 1.00 / 0.00 / 0.05 |
| ask, k=4 | p50 0.28 s, p90 0.34 s | p50 0.17 s, p90 0.21 s |
| 1 user | 4.9 q/s, p50 0.21 s | 4.9 q/s, p50 0.19 s |
| 2 users | 5.0 q/s, p50 0.37 s, p90 0.57 s | 1.7 q/s, p50 0.39 s, p90 6.9 s |
| 4 users | 3.7 q/s, p50 0.57 s, p90 2.1 s | 6.7 q/s, p50 0.58 s, p90 0.83 s |
| 8 users | 6.7 q/s, p50 1.07 s, p90 1.34 s | 7.1 q/s, p50 1.04 s, p90 1.29 s |

An answer is now 8x (English) to 11x (Chinese) faster than on 32 vCPUs, and 8 users get
25x the CPU throughput (7 q/s against 0.29): generation runs at 330–390 tokens/s and prompt
processing is no longer the budget, so the per-user cost is retrieval plus a few hundred
milliseconds of generation. The Chinese/English gap shrinks from 2.3x to 1.6x because the
longer Chinese prompts are cheap on the GPU. Quality is unchanged (same models), the
negative-rejection weakness is the same. The two p90 outliers (6.9 s at 2 users, 2.1 s at
4 users) are single slow requests, not errors; with the first configuration of the GPU
image the embedding server also took ~9 s for its first request after start (warm-up).

Nothing here is confidential-computing overhead in the GPU sense: the same llama.cpp build
on an unprotected H200 was not measured in this round, and the 4–8 % that the ETH Zurich study reports for
Hopper confidential mode (paper, related work) is well below the run-to-run noise of a 100-question sample.
The GPU session costs show up in "connect": verifying the SPDM transcript (ECDSA P-384
over 64 measurement blocks) and the 5-certificate chain adds ~30 ms over the CPU-only
session.

### Generator size: Qwen2.5-7B-Instruct on the GPU (step-11 image, 2026-10-23)

Same GPU configuration, same corpus and questions, generator swapped for Qwen2.5-7B-Instruct
Q4_K_M (the 1.5B file stays in the image; `CHAT_MODEL=1.5b` in `guest-llm-setup.sh`
selects it). 7.7 GB of device memory, 334 tokens/s became ~130 tokens/s.

| | 1.5B zh | 7B zh | 1.5B en | 7B en |
|---|---|---|---|---|
| answer accuracy (RGB alias match) | 0.95 | **0.99** | 0.975 | 0.975 |
| held out: rejection ("context insufficient") | 0.05 | **0.35** | 0.05 | **0.35** |
| false rejection on answerable questions | 0.00 | 0.00 | 0.00 | 0.025 |
| held out: answered correctly from memory | 0.00 | 0.00 | 0.05 | 0.10 |
| ask, k=4, p50 / p90 | 0.28 / 0.34 s | 0.62 / 0.87 s | 0.17 / 0.21 s | 0.46 / 0.63 s |
| 8 users: q/s, p50 | 6.7, 1.07 s | 2.6, 2.64 s | 7.1, 1.04 s | 3.6, 1.87 s |

The size change buys exactly what the small model lacked: negative rejection goes from 5 %
to 35 % in both languages (7 of 20 held-out questions refused instead of 1), Chinese
accuracy rises to 0.99, and the English model now also answers 2 more held-out questions
correctly from pretraining. 35 % is still not a safe gate (RGB reports ~45 % for ChatGPT on
its harder noise setting); the remaining fix is a relevance threshold or verifier pass, not a
bigger model. Cost: 2.5x the single-user latency and half the 8-user throughput, both still
far inside the CPU-only envelope (1.4–3.2 s single user, 0.3 q/s at 8 users). The first
request after model load took 35 s (CUDA warm-up) and is the "max" in `bench-gpu7b-*.json`;
exclude it when quoting tails.

### What confidential computing costs: the same pipeline in a plain VM (A1, 2026-10-23)

Unprotected baseline: the identical step-11 image booted as an ordinary QEMU VM (no SEV-SNP,
standard OVMF, `launch-snpvm.sh plain`), GPU3 switched to normal mode with NVIDIA's admin tool
and passed through the same way, both llama servers on CUDA, the node started with
`--attester mock-insecure` and the KBS/client with `--insecure-mock` (a public mock vendor,
`policies/insecure-baseline.json`; it proves nothing and exists only for this comparison).
Everything else is byte-identical: models, corpus, questions, sealing, HTTP path.

| 7B generator, GPU | CVM + CC GPU | plain VM + plain GPU | overhead |
|---|---|---|---|
| session setup (attestation + policy) | 0.062 s | 0.017 s (mock) | +45 ms |
| en: ask p50 / p90 | 0.46 / 0.63 s | 0.36 / 0.53 s | +30 % / +18 % |
| zh: ask p50 / p90 | 0.62 / 0.87 s | 0.54 / 0.76 s | +16 % / +14 % |
| en: 1 user (sweep) p50 | 0.44 s | 0.28 s | +57 % |
| en: 8 users q/s | 3.55 | 4.21 | −16 % |
| zh: 8 users q/s | 2.64 | 3.36 | −21 % |
| accuracy / rejection | 0.975 / 0.35, 0.99 / 0.35 | 0.975 / 0.35, 0.99 / 0.30 | none |

So the end-to-end price of confidential computing for this pipeline is 16–30 % on the median
answer at one user and 16–21 % of throughput at eight, with the quality unchanged. That is
more than the 4–8 % reported for the model call alone on Hopper at large batch: at batch 1 a
7B decode is a stream of small kernels, and in CC mode every submission crosses the encrypted
driver/GPU channel, so launch latency rather than compute dominates; the CVM adds bounce
buffering for every virtio and GPU DMA on top. Batching (8 users) amortises the first part,
which is why the gap narrows. The 10 % end-to-end target therefore holds only under load,
not for a single interactive user. The first request after model load takes ~30 s in both
configurations (CUDA warm-up, not CC).

**What could not be measured.** The GPU half of the overhead cannot be isolated by attaching
a normal-mode GPU to the SEV-SNP VM: the NVIDIA driver refuses
(`confComputeConstructEngine: GPU confidential compute capability is not enabled … Cannot
attach gpu`), so inside a CVM the GPU must be in CC mode. The two halves (CVM, CC GPU) are
only separable with a plain VM plus a CC-mode GPU, which NVIDIA does not support either.

### Session cost with NVIDIA's services (RIM + OCSP, 2026-10-24)

With `--gpu-rim` the client (or KBS) also fetches the driver and VBIOS reference manifests,
verifies their XML signatures and chains, compares the 22 active driver entries with the
report, and asks NVIDIA's OCSP responder about the 3 CA certificates of the attestation-key
chain and the 3 of the manifest chain. Measured on h200 with the SDK's `verify` against the
live node:

| session | wall time |
|---|---|
| SNP + GPU transcript, no NVIDIA services | 0.21 s |
| + manifests and OCSP, cold cache (1 manifest fetch, 6 OCSP round trips) | 3.27 s |
| + manifests and OCSP, warm cache | 0.23 s |

Manifests are immutable per id and OCSP responses are valid for a day, so the cold path is
paid once per verifier, not per session. A client that skips the services against a policy
with `require_gpu_ocsp` is refused before it uploads anything (`gpu[0]: certificate
revocation not checked`).

## Reproduce

```bash
# on the h200 host, node running (deploy/h200/README.md); ~/snp/venv has attestrag
python scripts/rag_bench.py --node http://127.0.0.1:8081 --policy ~/snp/policy-h200.json \
    --dataset zh_refine --limit 100 --holdout 0.2 --seed 7 --sweep 1,2,4,8 --out bench-zh.json
# corpus persists in the sealed Qdrant snapshot: later runs can pass --skip-ingest
```

Raw results: `bench-{zh,en}_refine.json`, `bench-*-sweep.json`, `bench-gpu-*.json` (GPU, 1.5B) and
`bench-gpu7b-*.json` (GPU, 7B) and `bench-plain7b-*.json` (plain VM baseline) on h200 in `~/snp`
(per-question answers, hits, latencies). The RGB files are downloaded to
`~/.cache/attestrag/rgb/` on first use.
