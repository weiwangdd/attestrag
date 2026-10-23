/-!
# Claims and policy data

Mirrors `attestrag/attest/types.py` and the `Policy` dataclass in
`attestrag/policy/engine.py`. Only what the key-release decision reads is modelled;
signatures and certificate chains are checked by the Python verifier before any
`Claims` value exists, and appear here only as an opaque `sigsOk` flag
(see `AttestRAG.Release`).

Modelling choices (see `docs/lean-correspondence.md` for the full list):
* byte strings are `List UInt8`;
* timestamps and durations are integers (Python uses `float` seconds);
* a TCB is an association list `component ↦ SVN` (a Python `dict[str, int]`);
* the SNP guest policy is already parsed to a number (Python keeps the raw string in
  `Claims.extra["guest_policy"]` and parses it in the engine).
-/

namespace AttestRAG

abbrev Bytes := List UInt8

/-- `attestrag.attest.types.Platform` -/
inductive Platform where
  | sevSnp
  | tdx
  | nvidiaCC
  | mockCpu
  | mockGpu
  deriving DecidableEq, Repr

/-- `Platform.is_gpu` -/
def Platform.isGpu : Platform → Bool
  | .nvidiaCC | .mockGpu => true
  | _ => false

/-- Component-wise trusted computing base: component name ↦ security version number. -/
abbrev Tcb := List (String × Nat)

/-- `attestrag.attest.types.Claims`: verified, normalised claims from one report. -/
structure Claims where
  platform : Platform
  measurement : String
  tcb : Tcb
  reportData : Bytes
  debug : Bool
  issuedAt : Int
  /-- `extra["guest_policy"]`, parsed. `none` = not reported. -/
  guestPolicy : Option Nat := none
  deriving Repr

/-- `attestrag.attest.types.CompositeClaims`: one CPU report plus GPU reports. -/
structure CompositeClaims where
  cpu : Claims
  gpus : List Claims := []
  deriving Repr

/-- `attestrag.policy.engine.Policy`. Measurement allow-lists are assumed already
lower-cased, as `Policy.from_dict` does on load. An empty `allowedGpuMeasurements`
or `allowedGuestPolicy` means "not checked", exactly as in Python. -/
structure Policy where
  allowedCpuPlatforms : List Platform
  allowedMeasurements : List String
  minTcb : Tcb := []
  allowDebug : Bool := false
  maxAge : Int := 300
  clockSkew : Int := 30
  requireGpu : Bool := false
  allowedGpuPlatforms : List Platform := []
  allowedGpuMeasurements : List String := []
  minGpuTcb : Tcb := []
  allowedGuestPolicy : List Nat := []
  deriving Repr

end AttestRAG
