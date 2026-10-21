# Lean specification of key release ↔ Python code

`lean/` holds a Lean 4 model of the trusted core that decides whether a data key is
released: the `report_data` binding, the CPU↔GPU binding, the policy engine
(including the component-wise minimum TCB) and the KBS release path. It does not
cover the vector store, embeddings, retrieval or the model.

Build: `cd lean && lake build` (Lean `v4.34.1`, pinned in `lean/lean-toolchain`, no
Mathlib). CI runs it with `--wfail`, so a `sorry` fails the build.

## What is proved

| Theorem (`lean/AttestRAG/…`) | Statement |
|---|---|
| `Release.release_iff` | `release` returns `true` **iff** every condition holds: nonce live, key id known, signatures OK, CPU/GPU slots right, CPU `report_data` = `cpu_report_data(nonce, pk)`, every GPU `report_data` = `gpu_report_data(cpu.report_data)`, and the policy is satisfied (`Admissible`). |
| `Release.no_release_of_*` | One corollary per condition: if it fails, no key. (dead nonce, unknown key, bad signature, CPU unbound, GPU unbound, policy, CPU TCB below / missing, GPU TCB) |
| `Policy.evaluate_iff` | `evaluate` (rule-by-rule mirror of `engine.evaluate`) allows exactly the claims satisfying the declarative `Admissible` spec. |
| `Policy.evaluate_false_of_*` | One corollary per policy rule (platform, debug, measurement, TCB, freshness, guest policy, GPU required, any GPU failing). |
| `Tcb.tcbReasons_eq_nil` | `check_min_tcb` gives no reasons iff every required component is present and ≥ its minimum. |
| `Tcb.no_compensation`, `not_tcbOk_of_below` | A component below its minimum fails regardless of other components (not lexicographic). |
| `Tcb.TcbOk.mono` | Upgrading components never turns a pass into a fail. |
| `Binding.cpuReportData_inj` | *(hash assumption)* The CPU `report_data` pins the nonce and the TEE public key. |
| `Binding.gpuReportData_inj`, `cpu_ne_gpu` | *(hash assumption)* GPU `report_data` pins the CPU `report_data`; a GPU binding value is never a valid CPU binding value. |
| `Release.release_pins_session` | *(hash assumption)* Two accepted requests with the same CPU report have the same nonce and public key. |
| `Release.gpu_not_replayable`, `gpu_pins_session` | *(hash assumption)* A GPU report accepted in two requests forces the same CPU report, nonce and public key: GPU evidence is good for exactly one session. |
| `Release.nonce_single_use` | After any `request_key`, the same nonce never releases a key again. |
| `Examples.*` | `policies/h200-genoa.json` and the cases of `tests/test_policy.py`, plus full `release` runs, decided by the kernel. |

The "hash assumption" is the hypothesis `CollisionFree H`: SHA-384 over the
length-prefixed part list is injective. It is passed explicitly to each theorem that
uses it; nothing is declared with `axiom`. All theorems depend only on Lean's
standard axioms (`propext`, `Classical.choice`, `Quot.sound`).

## Code mapping

| Python | Lean |
|---|---|
| `attest/types.py` `Platform`, `.is_gpu` | `Types.Platform`, `Platform.isGpu` |
| `attest/types.py` `Claims`, `CompositeClaims` | `Types.Claims`, `Types.CompositeClaims` |
| `policy/engine.py` `Policy` | `Types.Policy` |
| `common/crypto.py` `sha384(*parts)` | `Binding.HashModel.digest` (abstract) |
| `attest/binding.py` `CPU_RD_LABEL`, `GPU_RD_LABEL` | `Binding.cpuLabel`, `Binding.gpuLabel` |
| `attest/binding.py` `cpu_report_data`, `gpu_report_data` | `Binding.cpuReportData`, `Binding.gpuReportData` |
| `policy/engine.py` `check_min_tcb` | `Tcb.tcbReasons` (spec: `Tcb.TcbOk`) |
| `policy/engine.py` `_freshness` | `Policy.freshReasons` (spec: `Policy.Fresh`) |
| `evaluate`, guest-policy block | `Policy.guestPolicyReasons` (spec: `GuestPolicyOk`) |
| `evaluate`, CPU block | `Policy.cpuReasons` (spec: `CpuOk`) |
| `evaluate`, `for i, g in enumerate(claims.gpus)` | `Policy.gpuReasons`, `Policy.gpusReasons` (spec: `GpuOk`) |
| `evaluate` → `Decision.reasons` / `.allow` | `Policy.reasons` / `Policy.evaluate` (spec: `Admissible`) |
| `attest/base.py` `CompositeVerifier.verify` slot checks | `Release.slotsOk` |
| `CompositeVerifier.verify` + per-platform `verify` `report_data` comparison | `Release.bindingOk` (spec: `Release.Bound`) |
| `kbs_client/reference_kbs.py` `ReferenceKBS.request_key` | `Release.release` (spec: `MayRelease`), stateful: `Release.requestKey` |
| `ReferenceKBS._nonces`, `challenge`, `pop` | `Release.KbsState.nonces`, `filter` in `requestKey` |

### Reason strings

| Python message | `Reason` constructor |
|---|---|
| `{s}: platform {p} not allowed` | `platformNotAllowed s p` |
| `{s}: debug mode enabled` | `debugEnabled s` |
| `{s}: measurement not in allow-list` | `measurementNotAllowed s` |
| `{s}: tcb component '{c}' missing` | `tcbMissing s c` |
| `{s}: tcb '{c}'={have} < required {need}` | `tcbTooLow s c have need` |
| `{s}: evidence issued in the future` | `issuedInFuture s` |
| `{s}: evidence older than {max_age}s` | `tooOld s` |
| `cpu: guest policy not reported` | `guestPolicyMissing` |
| `cpu: guest policy {gp} not in allow-list` | `guestPolicyNotAllowed gp` |
| `gpu: GPU evidence required but none presented` | `gpuRequired` |

`s` is `Subject.cpu` (`"cpu"`) or `Subject.gpu i` (`"gpu[i]"`).

## Where the model differs from the code

These are deliberate abstractions. Each one is a place where a Python change could
diverge from the Lean model without Lean noticing, so keep them in mind when editing
either side.

1. **Cryptography is not modelled.** Signature and certificate-chain verification is
   the boolean `Request.sigsOk`; SHA-384 is the abstract `HashModel`. The binding
   theorems are only as good as `CollisionFree` (an idealisation of collision
   resistance; there is no adversary or probability in the model).
2. **`report_data` padding.** The SNP verifier compares the 64-byte field with
   `expected.ljust(64, b"\0")` and puts the unpadded expected value into `Claims`.
   Lean compares the unpadded value directly. Equivalent because the CPU binding is a
   fixed-length 48-byte digest.
3. **Time is `Int`, Python uses `float`.** A `NaN` `issued_at` would pass both Python
   freshness comparisons. Today `issued_at` comes from the verifier's clock (SNP) or a
   signed mock report, so this is not reachable, but `_freshness` does not reject it.
4. **Normalisation happens before the model.** `Policy.from_dict` lower-cases
   measurement allow-lists and parses `allowed_guest_policy`; Lean takes those as
   already normalised. The guest policy in `Claims` is `Option Nat` in Lean but a hex
   string in `Claims.extra`; if `_to_int` raises on a malformed value, Python raises
   an exception from `evaluate` (no key is released, but also no audit record) instead
   of returning a reason. Python `str.lower` is Unicode, Lean `String.toLower` is
   ASCII; they agree on hex.
5. **TCB as association list.** Python dicts have unique keys; `List.lookup` uses the
   first match. A policy JSON with a duplicated component keeps the last value in
   Python. Reason order also differs (Python sorts components), which never affects
   `allow`.
6. **The nonce state** models `_nonces` and single use, not expiry bookkeeping beyond
   `now ≤ expiry`, and not concurrency (Python `ReferenceKBS` is single-threaded).

## Keeping the two in sync

When a rule is added to `engine.evaluate`, add the matching branch to
`Policy.cpuReasons`/`gpuReasons`, a conjunct to `CpuOk`/`GpuOk`, and an
`evaluate_false_of_*` corollary; `evaluate_iff` will stop compiling until the proof is
updated. A shared test-vector file checked by both pytest and Lean would turn the
remaining manual step (reading both sides) into a CI check; it is not done yet.
