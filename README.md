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
> are implemented and validated on real hardware (self-hosted EPYC Genoa host, see
> `deploy/h200`); a real signed report is the golden sample in
> `tests/fixtures/snp/h200-genoa/`. TDX / NVIDIA CC are placeholders. Not for production.

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
  sdk/         client: verify evidence, then encrypted upload/query (+ HTTP transport, CLI)
  node.py      the in-CVM service tying it together (+ HTTP routes)
  transport.py JSON-over-HTTP wire format, stdlib server/client
  kbs_server.py   KBS as an HTTP service (runs outside the CVM)
  node_server.py  node as an HTTP service (runs inside the CVM)
  demo.py      local end-to-end demo
policies/    reference key-release policies (h200-genoa.json: measurement allow-list, min TCB, guest policy)
deploy/gcp/  GCP N2D SEV-SNP VM deploy script
deploy/h200/ self-hosted SEV-SNP CVM: QEMU launcher, reproducible dm-verity image build, reference measurements
tests/       unit + end-to-end tests, incl. a real Genoa report (fixtures/snp/h200-genoa)
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

## Three processes: KBS outside, node inside, client anywhere

```bash
# data owner's machine (outside the CVM): holds the keys, enforces the policy
python -m attestrag.kbs_server --policy policies/h200-genoa.json --keys kbs-keys.json --listen 0.0.0.0:8800

# inside the SEV-SNP guest (root): attests to the KBS, gets the index key, serves the RAG API
sudo python -m attestrag.node_server --kbs http://<kbs-host>:8800 --data-dir /var/lib/attestrag

# client: verifies the node's evidence against its own policy before sending anything
python -m attestrag.sdk --node http://<node>:8080 --policy policies/h200-genoa.json upload doc.md
python -m attestrag.sdk --node http://<node>:8080 --policy policies/h200-genoa.json ask "..."
```

Documents and questions are encrypted to the X25519 key bound into the node's report; the
answer is sealed with a one-time key carried inside the encrypted question, so only the
attested node can produce an answer the client accepts. No TLS is needed for that, but a
deployment may add it for metadata privacy.

## Real SEV-SNP on your own host

`deploy/h200/` runs a CPU-only SNP guest with QEMU directly (no libvirt), measures the
whole boot chain (OVMF + kernel/initrd/cmdline via `kernel-hashes`, root filesystem via
dm-verity with the root hash on the cmdline) and rebuilds the image reproducibly so the
expected measurement can be recomputed by anyone. The resulting values are in
`policies/h200-genoa.json`; use them instead of TOFU:

```bash
sudo python -m attestrag.demo --snp --policy policies/h200-genoa.json
```

## Roadmap

1. ✅ Mock end-to-end: verify → release key → encrypted ingest → retrieve → generate
2. ✅ SEV-SNP attester + verifier validated on real hardware (EPYC Genoa, `deploy/h200`); reference measurement + policy published (`policies/h200-genoa.json`); GCP N2D still untested
3. TDX quote verification (DCAP); NVIDIA CC GPU evidence (NRAS / local verifier)
4. ✅ HTTP transport: KBS outside the CVM, node inside, CLI client (validated on h200). Trustee KBS integration later
5. Lean specification of the policy engine; differential testing Python ↔ Lean
6. Local LLM (llama.cpp) inside the CVM; attested remote inference endpoints

## License

Apache-2.0
