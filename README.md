# AttestRAG

Open-source, end-to-end **attestable RAG** that you deploy into your own cloud
account. The whole pipeline — parsing, embedding, vector index, retrieval and
generation — runs inside a CPU confidential VM (AMD SEV-SNP / Intel TDX).
Generation uses either a local small model in the same CVM or an attested
inference API.

What makes it different:

- **CPU + GPU composite attestation**: GPU evidence is bound to the CPU report
  of the same session (`attest/binding.py`), so spliced/replayed GPU reports fail.
- **Keys only after proof**: the index data-encryption key is released by a KBS
  only after evidence verifies *and* the policy passes — including
  component-wise **minimum TCB** checks (`policy/engine.py`).
- **Clients verify before sending**: the SDK refuses to upload or query until the
  node's evidence is verified against the client's own policy; payloads are
  encrypted to a key bound into the attestation report.
- **Formal policy (planned)**: the policy engine is a small total function so it
  can be specified and proved in Lean.

> Status: milestone 1 — full flow works locally with **mock** attestation.
> SEV-SNP attester (configfs-tsm) and verifier (pinned AMD ARK → ASK → VCEK via KDS)
> are implemented and unit-tested against synthetic reports; they have not yet run on
> real hardware. TDX / NVIDIA CC are placeholders. Not for production.

## Layout

```
attestrag/
  attest/      Attester/Verifier interfaces, CPU<->GPU binding, mock, SEV-SNP (+ bundled AMD roots), TDX stub
  policy/      evidence claims -> allow/deny (measurement, debug, freshness, min TCB, GPU)
  kbs_client/  TEE-side KBS client + in-process reference KBS
  ingest/      parsing + chunking
  embed/       embedders (offline hashing embedder for now)
  index/       vector index (FAISS or numpy), AES-GCM-encrypted at rest
  retrieve/    top-k retrieval
  generate/    stub generator / OpenAI-compatible endpoint (llama.cpp server)
  sdk/         client: verify evidence, then encrypted upload/query
  node.py      the in-CVM service tying it together
  demo.py      local end-to-end demo
tests/         unit + end-to-end tests
docs/threat-model.md
```

## Run

Requires Python 3.11+.

```bash
./scripts/bootstrap.sh          # or: python3.11 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python -m attestrag.demo
```

## Real SEV-SNP on GCP

`deploy/gcp/snp-vm.sh` creates an N2D Confidential VM (AMD Milan, SEV-SNP, Spot by
default), copies the working tree, runs the tests and `python -m attestrag.demo --snp`.

```bash
gcloud auth login
gcloud config set project <PROJECT_ID>
gcloud services enable compute.googleapis.com
GCP_ZONE=us-central1-a deploy/gcp/snp-vm.sh up     # creates billable resources
deploy/gcp/snp-vm.sh down                           # delete when done
```

`DRY_RUN=1 deploy/gcp/snp-vm.sh up` prints the gcloud commands without running them.

## Roadmap

1. ✅ Mock end-to-end: verify → release key → encrypted ingest → retrieve → generate
2. 🚧 SEV-SNP attester + verifier implemented; validate on a GCP N2D SNP VM, publish reference measurements
3. TDX quote verification (DCAP); NVIDIA CC GPU evidence (NRAS / local verifier)
4. HTTP transport; integrate with Trustee KBS; reproducible CVM image + published measurements
5. Lean specification of the policy engine; differential testing Python ↔ Lean
6. Local LLM (llama.cpp) inside the CVM; attested remote inference endpoints

## License

Apache-2.0
