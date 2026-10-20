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
| Guest launched with migration agent, SMT or other policy bits the deployment forbids | `allowed_guest_policy` allow-list on the SNP GUEST_POLICY (e.g. `0x30000`) |
| Known-vulnerable firmware/microcode | component-wise `min_tcb` (no lexicographic compensation) |
| Evidence replay | single-use, expiring KBS nonce; `max_age_s` freshness |
| Key stolen in transit / evidence for another key | `report_data = H(nonce ‖ tee_pubkey)`; key wrapped (X25519+HKDF+AES-GCM) to that pubkey |
| GPU evidence spliced from another session | GPU `report_data = H(label ‖ cpu_report_data)` |
| Host reads/edits index on disk | AES-256-GCM with AAD (format, dim); tamper ⇒ load fails |
| Client data sent to impostor node | SDK verifies evidence + policy before any upload; data encrypted to the attested transport key |
| Answer forged or swapped on the network | answer sealed (AES-GCM) with a one-time key the client put inside the question encrypted to the attested node key; a forger cannot know it |
| Host swaps kernel, initrd, cmdline or any file on the root filesystem | `kernel-hashes` puts kernel/initrd/cmdline in the launch measurement; the cmdline carries the dm-verity root hash of a read-only rootfs, so the whole boot chain is one measurement (`deploy/h200`, reproducible build) |

## Known gaps / out of scope (for now)

### Reference KBS (`kbs_client/reference_kbs.py`, `kbs_server.py`)
- Keys live in process memory plus a plaintext JSON file (0600) on the KBS host;
  no HSM / KMS backing, no key rotation or revocation.
- One policy for all key ids; no per-key or per-tenant policy, no policy versioning
  or signed policy updates.
- Audit records are an in-memory list plus one stderr line per request; nothing
  durable or tamper-evident.
- Nonces are in memory: a KBS restart forgets outstanding challenges (harmless,
  clients retry) and a single instance only, no shared state for several replicas.
- No TLS, no client authentication: anyone who can reach the port can request a
  challenge and present evidence. Release still requires valid evidence, but the
  endpoint is open to probing and DoS.
- No index version counter: a rolled-back `index.enc` decrypts fine (see rollback
  below).
- Freshness relies entirely on the single-use nonce (SNP reports carry no time);
  `max_age_s` is inert for SNP because `issued_at` is the verification time.
- The verifier fetches VCEKs from AMD KDS on first sight of a chip/TCB and caches
  them on disk; an offline KBS needs a pre-populated cache.
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
  counter or version bound in the KBS). On h200 the index lives on a plain
  host-provided ext4 disk (`/var/lib/attestrag`): its filesystem metadata is
  untrusted input to the guest kernel, and the host can roll it back or wipe it.
- Remote inference APIs are not yet attested before use.
- HTTP without TLS: metadata (doc ids, sizes, timing, error reasons from the KBS) is
  visible to the network; `ingest`'s chunk count reply is unauthenticated.
- Measured boot covers userspace only on the self-hosted image (`deploy/h200`);
  the GCP image is not yet built this way. Guest writes are ephemeral (tmpfs overlay),
  so persistent state must come through the attested KBS/index path.
