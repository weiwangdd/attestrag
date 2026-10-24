# Executable policy specification (Lean 4)

`AttestRAG/Policy.lean` is `attestrag/policy/engine.py::evaluate` written again in Lean 4
(core library only, no Mathlib): the same structures, the same rules in the same order and the
same reason strings byte for byte. `Main.lean` wraps it into a binary that reads
`{"policy": ..., "claims": {"cpu": ..., "gpus": [...]}, "now": <seconds>}` on stdin and prints
`{"allow": bool, "reasons": [...]}`, so the specification is also an oracle.

```
cd formal/lean && lake build          # Lean 4.35 via elan; ~1 min, no network after the toolchain
echo '{"policy": {...}, "claims": {...}, "now": 1792800000}' | .lake/build/bin/attestrag_policy
cd ../.. && .venv/bin/python -m pytest tests/test_lean_policy.py   # differential test against the engine
```

## Theorems (`AttestRAG/Theorems.lean`)

| theorem | statement |
|---|---|
| `allow_iff_no_reasons` | `allow` holds iff the reason list is empty |
| `deny_of_mem_reasons` | any reason denies |
| `deny_of_cpu_debug` | CPU debug mode with `allow_debug = false` denies |
| `deny_of_cpu_measurement` | a measurement outside the allow-list denies |
| `deny_of_missing_gpu` | `require_gpu` with no GPU claims denies |
| `checkMinTcb_mem_of_short`, `deny_of_cpu_tcb_short` | one TCB component below its minimum denies, whatever the other components are (component-wise, never lexicographic) |
| `checkMinTcb_mem_of_missing`, `deny_of_cpu_tcb_missing` | a required component the report does not carry denies |
| `allow_mono_measurements` | enlarging the measurement allow-list never turns an allow into a deny |

## Differential test

`tests/test_lean_policy.py` generates 500 random policy/claims pairs (all platforms, random
allow-lists, TCB vectors with missing and short components, debug, freshness around every
boundary, guest-policy strings in hex and decimal, RIM/OCSP extras, 0–2 GPUs) and runs the
published h200 policy against the verified claims of the composite golden fixture plus six
variations; every case must produce the same `allow` and the same reasons in both
implementations. The input side is where the two differ by construction: the spec takes whole
seconds, expects `min_tcb` sorted by component (the loader sorts) and denies an unparsable
`guest_policy` string where the engine raises.
