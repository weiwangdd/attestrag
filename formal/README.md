# Formal analysis

Two parts: the release *protocol* in Tamarin (this file) and the *policy function* as an
executable Lean 4 specification with a differential test against the Python engine
(`lean/README.md`).

## Protocol model (Tamarin)

Tamarin models of the protocol that `attestrag/kbs_client/reference_kbs.py`, `attestrag/attest/binding.py`,
`attestrag/common/crypto.py`, `attestrag/node.py` and `attestrag/sdk` implement. Run with
`formal/prove.sh` (tamarin-prover 1.12, maude 3.5.1; every lemma in its own process with
`--auto-sources`, 75 s wall on 32 cores for both theories).
`formal/check.sh` does the same and compares every verdict with `formal/expected.txt` (exit 1 on any
mismatch; the expected `falsified` lines are the two attacks the models are kept for). CI runs it on every push.

## What is modelled

| element | model |
|---|---|
| AMD PSP, NVIDIA root | one signing key each, never leaked (hardware vendors are trusted) |
| good TEE | measurement `'good'`; generates its transport key inside; one attached GPU with its own NVIDIA-certified key |
| other TEE | any other measurement; the adversary learns its key and can put anything into `report_data` |
| GPU | signs `<'gpureport', firmware, nonce>` for the nonce its driver passes; the good TEE's GPU only for that TEE's `h('gpu', rd)`; adversary-owned certified GPUs sign any nonce; GPUs with other firmware exist |
| KBS | single-use nonce (consumed even on failure), `rd = h('rd', nonce, pk)`, policy `'good'` / `'goodgpu'`, a version record per key, DEK and version released as `aenc(<DEK, v>, pk)` signed by the KBS identity; a commit `<v', h('commit', DEK, v')>` moves the record to `v'` |
| node | accepts a release only under the pinned KBS identity over its own nonce and pk; after an upload seals the document under the DEK as a fresh version and commits it |
| client | same verification, document uploaded as `aenc(doc, pk)`, question with a one-time reply key, answer sealed with it |
| adversary | Dolev-Yao network; runs TEEs with other images; owns certified GPUs |

Abstractions: SHA-384, HKDF and the commit HMAC as `h`, the X25519 + HKDF + AES-GCM wrap as asymmetric
encryption to `pk(x)` (only the holder of `x` opens it), index versions as fresh names (who may
introduce one is modelled, their order is not), the nonce TTL dropped (single use is the property
that matters), one DEK, the composite verifier's per-platform checks folded into signature
verification and the two measurement constants. Not modelled: side channels, physical attacks, firmware bugs
(the minimum-TCB policy's domain), the HTTP transport (no TLS; metadata is public anyway).

## Results

`attestrag_release_v1.spthy` (the protocol as first implemented, `attestrag-rd-v1`):

| lemma | property | result |
|---|---|---|
| `executable` | the full flow (release, unwrap, answered question) can happen | trace found |
| `dek_secrecy` | a released DEK is never known to the adversary | verified |
| `release_only_to_good_prover` | a release for nonce *n* to *pk* is preceded by the good TEE attesting over exactly *n*, *pk* | verified |
| `no_replay` | one release per nonce | verified |
| `gpu_bound_to_session` | the GPU report accepted with a session was signed over this session's `h('gpu', rd)` after the nonce was issued | verified |
| `gpu_is_the_attached_one` | the GPU whose report is accepted is the one attached to the attesting TEE | **falsified** |
| `doc_secrecy` | a document the client uploads after verification is never known to the adversary | verified |
| `answer_authentic` | an answer the client accepts was produced by the good TEE holding the key | verified |

The counterexample for `gpu_is_the_attached_one` is the residual gap Section 5.2 of the paper
states informally: `rd = h('rd', nonce, pk)` is public, so an operator who owns *another*
certified confidential GPU asks it to sign `h('gpu', rd)` for the victim session and swaps the GPU
half of the evidence in transit; the KBS sees a valid chain, the right firmware and the right
binding. Consequence: a host can hide a GPU with disallowed firmware behind one good GPU. The
session freshness property (`gpu_bound_to_session`) still holds, so evidence from *another
session* is rejected; what is not established is *which* GPU of this session's machine signed.

`attestrag_release.spthy` is the binding the code uses now (`attestrag-rd-v2`): one line changed,
`rd = h('rd', nonce, pk, pkg)`, with `pkg` the attestation key of the GPU the TEE's own driver
talks to (in the code: SHA-384 of the GPU's AK certificate, `attest.base.gpu_identity`, sorted
over all attached GPUs). Then `gpu_is_the_attached_one` is verified along with the other seven:
a substituted GPU half no longer matches the CPU report. `tests/test_gpu_identity_binding.py`
replays the attack against both bindings with mock GPUs.

The same theory now also carries the version record, the signed release, the persistence step and
the commit (step 17), with three more lemmas:

| lemma | property | `attestrag_release.spthy` | `attestrag_release_unsigned.spthy` |
|---|---|---|---|
| `release_authentic` | the key the good TEE holds was released to it by the KBS in a session it attested | verified | **falsified** (6 steps) |
| `version_authentic` | the version the good TEE accepts as its rollback floor is the one the KBS released to it | verified | **falsified** (6 steps) |
| `commit_authentic` | the KBS only records a version the good TEE sealed and committed | verified | verified |
| `doc_secrecy` | (as above, now with the sealed index on the untrusted disk) | verified | **falsified** (15 steps) |

`attestrag_release_unsigned.spthy` is the protocol as deployed before step 17: the release wrapped to
`pk` but not signed, so the node takes any well-formed `aenc(<DEK, v>, pk)`. The trace: the adversary
wraps a key of its own to the node's `pk`, the node accepts it, seals the uploaded document under it,
and the adversary opens the file on the disk it controls. The client's verification of the node is
no help, since the node is the measured image doing what it was told. The signature over
`<'release', nonce, pk, blob>` under the KBS identity, which the node pins (in the deployment the public
key sits in the measured `node.env`), closes it: the signed theory proves all eleven lemmas.
The version record is a persistent fact (the KBS may release any version it has recorded): with a
linear record Tamarin's search for the `executable` trace of the signed theory diverges, and the
lemmas say nothing about the order of versions anyway. That trace is the expensive one: 58 steps,
about 5 minutes and 7 GB of memory on a 32-core box, which is why CI proves each theory on its own
runner with the lemmas in sequence (`ONLY=<theory> JOBS=1 formal/check.sh`). In the unsigned theory
the same trace search costs 15 minutes and 17 GB (the adversary can wrap anything to the node), more
than a hosted runner has; that one line of `expected.txt` is marked `local-only` and skipped under
`CI=true`. Every other lemma of the three theories takes under a minute and 0.3 GB. The unsigned
model's non-vacuity is shown by its attack traces anyway.

## Reading the model

Rules are the protocol steps, action facts (in `--[ ]->`) are what the lemmas talk about,
restrictions encode `verify(...) = true` checks and "other image ≠ good". `--auto-sources` is
needed: without it Tamarin's precomputation does not terminate on the adversary-chosen inputs of
`TEE_Other_FreeReport` and `GPU_Adversary_Sign`.
