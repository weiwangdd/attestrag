import AttestRAG.Release

/-!
# Concrete checks

The policy shipped in `policies/h200-genoa.json` and cases mirroring
`tests/test_policy.py`, decided by the kernel (`decide +kernel`, no compiled code trusted), so the
model is exercised on real values and not only on symbols.
-/

namespace AttestRAG.Examples

/-- `policies/h200-genoa.json` -/
def h200Genoa : Policy where
  allowedCpuPlatforms := [.sevSnp]
  allowedMeasurements :=
    ["cae8d72f4018edbf2fb7d9a17df5b55132be2d6ca1e55d20d199b7fdf263426b5e90a001b76f2d09a25e96c0357f873d"]
  minTcb := [("bootloader", 10), ("tee", 0), ("snp", 24), ("microcode", 88)]
  allowedGuestPolicy := [0x30000]

def now : Int := 1_000_000

/-- A report that satisfies `h200Genoa` (upper-case hex, as some tools print it). -/
def goodCpu : Claims where
  platform := .sevSnp
  measurement :=
    "CAE8D72F4018EDBF2FB7D9A17DF5B55132BE2D6CA1E55D20D199B7FDF263426B5E90A001B76F2D09A25E96C0357F873D"
  tcb := [("bootloader", 10), ("tee", 0), ("snp", 24), ("microcode", 219)]
  reportData := []
  debug := false
  issuedAt := now - 5
  guestPolicy := some 0x30000

example : evaluate h200Genoa { cpu := goodCpu } now = true := by decide +kernel

-- unknown measurement
example : evaluate h200Genoa { cpu := { goodCpu with measurement := "ff" } } now = false := by
  decide +kernel

-- snp SVN 23 < 24, even with newer microcode
example : evaluate h200Genoa
    { cpu := { goodCpu with tcb := [("bootloader", 10), ("tee", 0), ("snp", 23), ("microcode", 250)] } }
    now = false := by decide +kernel

-- missing component
example : evaluate h200Genoa
    { cpu := { goodCpu with tcb := [("bootloader", 10), ("snp", 24), ("microcode", 219)] } }
    now = false := by decide +kernel

-- debug
example : evaluate h200Genoa { cpu := { goodCpu with debug := true } } now = false := by decide +kernel

-- stale (older than max_age 300s) and future (beyond 30s skew)
example : evaluate h200Genoa { cpu := { goodCpu with issuedAt := now - 301 } } now = false := by
  decide +kernel
example : evaluate h200Genoa { cpu := { goodCpu with issuedAt := now + 31 } } now = false := by
  decide +kernel

-- guest policy not reported / not allowed (e.g. MIGRATE_MA or debug bit set)
example : evaluate h200Genoa { cpu := { goodCpu with guestPolicy := none } } now = false := by
  decide +kernel
example : evaluate h200Genoa { cpu := { goodCpu with guestPolicy := some 0x70000 } } now = false := by
  decide +kernel

/-- GPU policy as in `test_gpu_required`. -/
def withGpu : Policy :=
  { h200Genoa with
    requireGpu := true
    allowedGpuPlatforms := [.nvidiaCC]
    minGpuTcb := [("vbios", 96), ("driver", 535)] }

def goodGpu : Claims where
  platform := .nvidiaCC
  measurement := "00"
  tcb := [("vbios", 96), ("driver", 550)]
  reportData := []
  debug := false
  issuedAt := now

example : evaluate withGpu { cpu := goodCpu } now = false := by decide +kernel
example : evaluate withGpu { cpu := goodCpu, gpus := [goodGpu, goodGpu] } now = true := by decide +kernel
example : evaluate withGpu
    { cpu := goodCpu, gpus := [goodGpu, { goodGpu with tcb := [("vbios", 96), ("driver", 470)] }] }
    now = false := by decide +kernel

/-! ## Full release with a toy hash

`toyHash` just concatenates the parts. It is *not* collision free and is used only to
run `release` on values; no theorem about binding is instantiated with it. -/

def toyHash : HashModel := ⟨fun parts => parts.flatten⟩

def nonce : Bytes := [1, 2, 3]
def pk : Bytes := [9, 9]
def cpuRd : Bytes := cpuReportData toyHash nonce pk

def boundClaims : CompositeClaims :=
  { cpu := { goodCpu with reportData := cpuRd },
    gpus := [{ goodGpu with reportData := gpuReportData toyHash cpuRd }] }

def req (cc : CompositeClaims) (k : Bytes := pk) : Request :=
  { nonceLive := true, keyKnown := true, sigsOk := true, nonce, teePubkey := k, claims := cc }

example : release toyHash withGpu (req boundClaims) now = true := by decide +kernel

-- key requested for a different public key than the one in report_data
example : release toyHash withGpu (req boundClaims [7]) now = false := by decide +kernel

-- GPU report bound to another session
example : release toyHash withGpu
    (req { boundClaims with gpus := [{ goodGpu with reportData := gpuReportData toyHash [0] }] })
    now = false := by decide +kernel

-- GPU evidence in the CPU slot
example : release toyHash withGpu
    (req { boundClaims with cpu := { boundClaims.cpu with platform := .nvidiaCC } }) now = false := by
  decide +kernel

end AttestRAG.Examples
