# Lean specification of key release

Lean 4 model and proofs for AttestRAG's trusted core: `report_data` binding,
CPU↔GPU binding, component-wise minimum TCB, the policy engine and the KBS release
decision. Main result: `AttestRAG.release_iff` (a key is released iff every
condition holds), with one `no_release_of_*` corollary per condition.

```bash
cd lean
lake build          # toolchain pinned in lean-toolchain; no Mathlib
```

| File | Contents |
|---|---|
| `AttestRAG/Types.lean` | claims, policy |
| `AttestRAG/Binding.lean` | `cpu_report_data` / `gpu_report_data`, injectivity under the hash assumption |
| `AttestRAG/Tcb.lean` | `check_min_tcb`, component-wise spec, no-compensation |
| `AttestRAG/Policy.lean` | `evaluate` mirror, declarative spec, `evaluate_iff` |
| `AttestRAG/Release.lean` | `request_key`, `release_iff`, replay and single-use nonce results |
| `AttestRAG/Examples.lean` | `policies/h200-genoa.json` and test cases decided by the kernel |

See `../docs/lean-correspondence.md` for the line-by-line mapping to the Python code
and the list of places where the model abstracts.
