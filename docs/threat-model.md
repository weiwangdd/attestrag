# Threat model (draft)

## Assets
- Customer documents, chunks, embeddings, vector index, queries and answers.
- The index data-encryption key (DEK) held by the KBS.

## Trust assumptions
- **Trusted**: CPU TEE hardware + firmware at or above the policy's minimum TCB
  (AMD SP / SEV firmware, Intel TDX module), GPU CC firmware when used, the
  measured AttestRAG CVM image, the KBS operated by the customer, the client SDK.
- **Untrusted**: the cloud provider's host OS / hypervisor / operators, storage,
  network, other tenants, and the AttestRAG operator if not the customer.

## Adversary capabilities
- Read/modify/replay anything on disk or on the network.
- Boot a modified image, enable debug, or run on outdated (vulnerable) TCB.
- Replay old evidence, or splice evidence from a different VM/session/GPU.

## Mitigations in this codebase
| Threat | Mitigation |
|---|---|
| Modified image | measurement allow-list (`policy.allowed_measurements`) |
| Debug CVM | `debug` claim must be false |
| Known-vulnerable firmware/microcode | component-wise `min_tcb` (no lexicographic compensation) |
| Evidence replay | single-use, expiring KBS nonce; `max_age_s` freshness |
| Key stolen in transit / evidence for another key | `report_data = H(nonce ‖ tee_pubkey)`; key wrapped (X25519+HKDF+AES-GCM) to that pubkey |
| GPU evidence spliced from another session | GPU `report_data = H(label ‖ cpu_report_data)` |
| Host reads/edits index on disk | AES-256-GCM with AAD (format, dim); tamper ⇒ load fails |
| Client data sent to impostor node | SDK verifies evidence + policy before any upload; data encrypted to the attested transport key |

## Known gaps / out of scope (for now)
- Mock attestation provides **no security**; TDX/NVIDIA verifiers are TODO.
- SEV-SNP: VLEK-signed reports are rejected (not yet supported); ARK pins are
  compiled in, so an AMD root rotation needs a release. Reports carry no
  timestamp — freshness relies entirely on the single-use KBS nonce. The
  `--snp` demo runs the KBS inside the same CVM and uses TOFU for the policy;
  it demonstrates plumbing, not a trust boundary.
- On GCP the launch measurement covers Google's UEFI firmware; reference values
  must come from Google's launch endorsements (gce-tcb-verifier), not TOFU.
- GPU binding above proves session freshness, not that the GPU is the one
  attached to this CVM over an SPDM-protected link; that needs the CVM to attest
  its GPU session (e.g. NVIDIA CC + measured driver in the CPU measurement).
- Side channels (cache, ciphertext side channels on SEV, page-fault patterns,
  access-pattern leakage of the vector index), availability/DoS.
- Rollback of the encrypted index to an older version (needs a monotonic
  counter or version bound in the KBS).
- Remote inference APIs are not yet attested before use.
- Measured boot coverage of the full userspace (needs a reproducible image,
  dm-verity rootfs, and published reference measurements).
