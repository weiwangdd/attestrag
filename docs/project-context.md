# AttestRAG — project context (handoff, 2026-10-15)

Summary of the confidential-RAG discussion and development so far, for seeding a new
project. Code lives in `~/src/attestrag` (local git, not pushed anywhere).

## Idea
Open-source, end-to-end **attestable RAG** deployed into the customer's own cloud
account. The whole pipeline (parsing, embedding, vector index, retrieval, generation)
runs inside a CPU TEE confidential VM (AMD SEV-SNP / Intel TDX). Generation uses a
local small model in the CVM or an attested inference API.

Differentiators:
- **CPU + GPU composite attestation**, GPU evidence bound to the CPU report of the same session.
- **Keys released only after proof**, including component-wise **minimum TCB** checks.
- Clients verify the node's evidence **before** sending any data.
- Policy engine kept small and pure so it can be **formalized in Lean** later.

Paper outline: https://claude.ai/code/artifact/18317d5d-c295-48fa-afb6-cfa2a69d16ab

## Decisions made
- Python 3.11+, Apache-2.0, modules: attest / policy / kbs_client / ingest / embed /
  index / retrieve / generate / sdk, plus node.py (in-CVM service).
- `report_data = SHA-384(nonce ‖ TEE ephemeral X25519 pubkey)`; KBS wraps the key to
  that pubkey. GPU `report_data = H(label ‖ cpu_report_data)`.
- Vector index encrypted at rest with AES-256-GCM (FAISS / numpy backend).
- First real-hardware target: **GCP N2D Confidential VM, SEV-SNP, Spot** (user chose GCP N2D).
- GPU: **a single GPU is enough** for MVP; must be CC-capable (H100/H200/Blackwell —
  L4/A10/A100 lack CC mode). 1×H100 runs 8B FP16 / 14–32B FP8-INT8 comfortably; 70B
  needs 4-bit or H200. Azure NCCadsH100v5 = SEV-SNP + H100 (matches our SNP verifier);
  GCP confidential H100 (A3) uses TDX (needs TDX verifier). GCP free trial can't use GPUs.
  Multi-GPU CC is a later premium tier.

## Status
- Milestone 1 ✅: mock attestation end to end (verify → release key → encrypted
  ingest → retrieve → generate). Commit 70563e1.
- Step 1 (real SEV-SNP) code done, unit-tested on synthetic reports, **not yet run on
  hardware**: configfs-tsm attester; verifier with bundled+pinned AMD ARK/ASK
  (Milan/Genoa/Turin), VCEK from AMD KDS (cached), VCEK hwID/TCB binding, ECDSA-P384.
  `python -m attestrag.demo --snp`. Deploy: `deploy/gcp/snp-vm.sh up|demo|ssh|status|down`.
  Commit d1caa05. 45 tests pass.

## Open items / next steps
1. User creates a Google Cloud account + project, installs gcloud, runs
   `deploy/gcp/snp-vm.sh up`; fix issues against a real report; save it as a golden test.
2. Plug llama.cpp (CPU, 3–8B quantized) into `generate` for demos.
3. HTTP transport for KBS/node; Trustee KBS integration.
4. Index rollback protection (version counter in KBS).
5. TDX (DCAP) verifier; NVIDIA CC GPU evidence verification; benchmark CC-mode overhead.
6. Lean specification of the policy engine; Python ↔ Lean differential tests.
7. Reference measurements: reproducible image; on GCP use Google launch endorsements
   (gce-tcb-verifier) instead of TOFU.

Known limitations: VLEK reports rejected; `--snp` demo runs KBS in the same CVM and uses
TOFU policy (plumbing only, not a trust boundary).
