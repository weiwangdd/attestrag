import AttestRAG.Types

/-!
# report_data binding

Mirrors `attestrag/attest/binding.py`:

    CPU:  report_data = SHA-384("attestrag-rd-v1"       ‖ nonce ‖ tee_pubkey)
    GPU:  report_data = SHA-384("attestrag-gpu-bind-v1" ‖ cpu_report_data)

where `‖` is the length-prefixed concatenation of `common.crypto.sha384(*parts)`.

SHA-384 is not computed here. It is a parameter `H : HashModel`, a function from the
list of parts to a digest. Results that need a property of the hash take
`CollisionFree H` (injectivity on part lists) as an explicit hypothesis. That is the
usual idealisation of collision resistance: because each part is length-prefixed, a
collision between two different part lists is a SHA-384 collision. Nothing here is a
probabilistic or computational statement.
-/

namespace AttestRAG

/-- The hash as used by `common.crypto.sha384(*parts)`. -/
structure HashModel where
  digest : List Bytes → Bytes

/-- Idealised collision resistance: distinct part lists never collide. -/
def CollisionFree (H : HashModel) : Prop :=
  ∀ a b, H.digest a = H.digest b → a = b

/-- `CPU_RD_LABEL = b"attestrag-rd-v1"` -/
def cpuLabel : Bytes := "attestrag-rd-v1".toUTF8.toList

/-- `GPU_RD_LABEL = b"attestrag-gpu-bind-v1"` -/
def gpuLabel : Bytes := "attestrag-gpu-bind-v1".toUTF8.toList

/-- `binding.cpu_report_data(nonce, tee_pubkey)` -/
def cpuReportData (H : HashModel) (nonce teePubkey : Bytes) : Bytes :=
  H.digest [cpuLabel, nonce, teePubkey]

/-- `binding.gpu_report_data(cpu_rd)` -/
def gpuReportData (H : HashModel) (cpuRd : Bytes) : Bytes :=
  H.digest [gpuLabel, cpuRd]

variable {H : HashModel}

/-- The CPU report_data pins both the session nonce and the TEE's public key. -/
theorem cpuReportData_inj (hH : CollisionFree H) {n n' pk pk' : Bytes}
    (h : cpuReportData H n pk = cpuReportData H n' pk') : n = n' ∧ pk = pk' := by
  have := hH _ _ h
  simp_all

/-- The GPU report_data pins the CPU report_data it was derived from. -/
theorem gpuReportData_inj (hH : CollisionFree H) {rd rd' : Bytes}
    (h : gpuReportData H rd = gpuReportData H rd') : rd = rd' := by
  have := hH _ _ h
  simp_all

/-- Domain separation: no GPU binding value can serve as a CPU binding value
(the part lists differ in length, independent of the labels). -/
theorem cpu_ne_gpu (hH : CollisionFree H) (n pk rd : Bytes) :
    cpuReportData H n pk ≠ gpuReportData H rd := by
  intro h
  have := hH _ _ h
  simp at this

end AttestRAG
