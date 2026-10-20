# AttestRAG — project context (handoff, 2026-10-15)

Summary of the confidential-RAG discussion and development so far. Code:
github.com/weiwangdd/attestrag (private), local clone `~/src/attestRAG`. Updated 2026-10-20.

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
  Commit d1caa05.
- Step 1 validated on real hardware 2026-10-20 (h200: Gigabyte G494, 2x EPYC 9554 Genoa,
  SEV firmware 1.55): attester (configfs-tsm in the guest) and verifier (KDS Genoa VCEK,
  pinned ARK) both worked unchanged; measurement reproduced offline by sev-snp-measure.
  `deploy/h200/` holds the QEMU launcher and a reproducible dm-verity image build;
  `policies/h200-genoa.json` the resulting policy; `tests/fixtures/snp/h200-genoa/` the
  real report as a golden test. 49 tests pass.
- 2026-10-20 (later): attestRAG itself runs inside the h200 CVM. `deploy/h200/guest-attestrag-setup.sh`
  installs the package + numpy/cryptography into `/opt/attestrag` of the golden image; the
  verity image was rebuilt (measurement 7e72a5b7...), `demo --snp --policy policies/h200-genoa.json`
  passes in the guest (KBS still in-process). A persistent, untrusted data disk
  (`images/data.qcow2`, mounted rw at `/var/lib/attestrag`; needs `overlayroot=tmpfs:recurse=0`
  or overlayroot hides it behind tmpfs) is ready for the encrypted index. Golden fixture updated.

## Open items / next steps
1. (done on h200 instead of GCP) GCP N2D path still unexercised; Milan VCEK/ARK untested
   against a real report.
2. (done 2026-10-20) llama.cpp in the CVM image: Qwen3-Embedding-0.6B (embeddings, dim 1024)
   + Qwen2.5-1.5B-Instruct Q4_K_M (generation), both sha256-pinned and measured; the guest
   boots into attest -> key -> serve via systemd. Bigger models need more vCPUs/RAM (vCPU
   count is part of the measurement) or the GPU step.
3. (done 2026-10-20) HTTP transport: `kbs_server` on the h200 host, `node_server` in the guest
   (reaches the host at 10.0.2.2 via slirp), `python -m attestrag.sdk` client; node :8080 is
   forwarded to host :8081. Trustee KBS integration later.
4. Index rollback protection (version counter in KBS). Vector DB: Qdrant inside the CVM
   (2026-10-20, `index/qdrant.py`, `deploy/h200/guest-qdrant-setup.sh`): tmpfs storage,
   sealed snapshots; whole-snapshot persistence per ingest is the known scaling limit. Other reference-KBS limits are
   listed in docs/threat-model.md (plaintext key file, single policy, in-memory audit
   and nonces, no TLS/client auth, no key rotation); replace with Trustee KBS or
   harden before any real deployment.
5. TDX (DCAP) verifier; NVIDIA CC GPU evidence verification; benchmark CC-mode overhead.
6. Lean specification of the policy engine; Python ↔ Lean differential tests.
7. Reference measurements: done for h200 (`deploy/h200/build-verity-image.sh`); on GCP
   use Google launch endorsements (gce-tcb-verifier) instead of TOFU.
8. GPU CC mode on one H200 NVL (open driver already installed on the host); NVIDIA
   evidence verification.

Known limitations: VLEK reports rejected; `--snp` demo runs KBS in the same CVM and uses
TOFU policy (plumbing only, not a trust boundary).
