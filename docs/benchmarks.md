# RAG benchmark on the h200 CVM

Measured 2026-10-20 against the running node on h200 (SEV-SNP guest, 32 vCPUs, 16 GB,
CPU-only llama.cpp: Qwen3-Embedding-0.6B Q8_0 + Qwen2.5-1.5B-Instruct Q4_K_M, Qdrant in tmpfs).
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

## Reproduce

```bash
# on the h200 host, node running (deploy/h200/README.md); ~/snp/venv has attestrag
python scripts/rag_bench.py --node http://127.0.0.1:8081 --policy ~/snp/policy-h200.json \
    --dataset zh_refine --limit 100 --holdout 0.2 --seed 7 --sweep 1,2,4,8 --out bench-zh.json
# corpus persists in the sealed Qdrant snapshot: later runs can pass --skip-ingest
```

Raw results: `bench-{zh,en}_refine.json` and `bench-*-sweep.json` on h200 in `~/snp`
(per-question answers, hits, latencies). The RGB files are downloaded to
`~/.cache/attestrag/rgb/` on first use.
