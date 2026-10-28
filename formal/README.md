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
mismatch; the one expected `falsified` is the attack on the first binding). CI runs it on every push.

## What is modelled

| element | model |
|---|---|
| AMD PSP, NVIDIA root | one signing key each, never leaked (hardware vendors are trusted) |
| good TEE | measurement `'good'`; generates its transport key inside; one attached GPU with its own NVIDIA-certified key |
| other TEE | any other measurement; the adversary learns its key and can put anything into `report_data` |
| GPU | signs `<'gpureport', firmware, nonce>` for the nonce its driver passes; the good TEE's GPU only for that TEE's `h('gpu', rd)`; adversary-owned certified GPUs sign any nonce; GPUs with other firmware exist |
| KBS | single-use nonce (consumed even on failure), `rd = h('rd', nonce, pk)`, policy `'good'` / `'goodgpu'`, DEK released as `aenc(DEK, pk)` |
| client | same verification, document uploaded as `aenc(doc, pk)`, question with a one-time reply key, answer sealed with it |
| adversary | Dolev-Yao network; runs TEEs with other images; owns certified GPUs |

Abstractions: SHA-384 and HKDF as `h`, the X25519 + HKDF + AES-GCM wrap as asymmetric encryption to
`pk(x)` (only the holder of `x` opens it), the nonce TTL dropped (single use is the property that
matters), one DEK, the composite verifier's per-platform checks folded into signature verification
and the two measurement constants. Not modelled: side channels, physical attacks, firmware bugs
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

## Reading the model

Rules are the protocol steps, action facts (in `--[ ]->`) are what the lemmas talk about,
restrictions encode `verify(...) = true` checks and "other image ≠ good". `--auto-sources` is
needed: without it Tamarin's precomputation does not terminate on the adversary-chosen inputs of
`TEE_Other_FreeReport` and `GPU_Adversary_Sign`.
