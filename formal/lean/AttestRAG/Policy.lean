/-!
# AttestRAG key-release policy, executable specification

Mirror of `attestrag/policy/engine.py::evaluate(policy, claims, now)`: a total, pure function
from a policy and verified claims to a decision with a list of reasons; `allow` holds iff the
list is empty. The strings are the engine's strings, byte for byte, so that the compiled
binary can be run against the Python engine on the same inputs (tests/test_lean_policy.py).

Deviations, all on the input side:
* times (`now`, `issuedAt`, `maxAgeS`, `clockSkewS`) are whole seconds (the engine uses floats);
* `min_tcb` / `min_gpu_tcb` must arrive sorted by component name (the engine sorts; the loader
  in Main.lean sorts);
* an unparsable `guest_policy` string denies here, where the engine raises.
-/
namespace AttestRAG

structure Claims where
  platform    : String                 -- Platform.value, e.g. "sev-snp", "nvidia-cc"
  measurement : String                 -- hex digest; compared lower-cased
  tcb         : List (String × Int)
  debug       : Bool
  issuedAt    : Int
  extra       : List (String × String) -- verifier extras: guest_policy, rim_driver, rim_vbios, ocsp, ...
  deriving Repr, Inhabited

structure CompositeClaims where
  cpu  : Claims
  gpus : List Claims
  deriving Repr, Inhabited

structure Policy where
  allowedCpuPlatforms    : List String
  allowedMeasurements    : List String        -- lower-case
  minTcb                 : List (String × Int) -- sorted by component
  allowDebug             : Bool := false
  maxAgeS                : Int := 300
  clockSkewS             : Int := 30
  requireGpu             : Bool := false
  allowedGpuPlatforms    : List String := []
  allowedGpuMeasurements : List String := []  -- empty = any
  minGpuTcb              : List (String × Int) := []
  requireGpuRim          : Bool := false
  requireGpuOcsp         : Bool := false
  allowedGuestPolicy     : List Int := []     -- empty = not checked
  deriving Repr, Inhabited

structure Decision where
  allow   : Bool
  reasons : List String
  deriving Repr, DecidableEq

def lower (s : String) : String := s.map Char.toLower

def hexVal (c : Char) : Option Nat :=
  if c.isDigit then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def parseHex (cs : List Char) : Option Int :=
  if cs.isEmpty then none else
  cs.foldl (fun acc c => match acc, hexVal c with
      | some a, some d => some (a * 16 + d)
      | _, _ => none) (some (0 : Int))

/-- Python's `int(v, 0)` for what a report carries: `0x...` hex, otherwise decimal. -/
def parseIntBase0 (t : String) : Option Int :=
  if t.startsWith "0x" || t.startsWith "0X" then parseHex (t.toList.drop 2)
  else if t.startsWith "-0x" || t.startsWith "-0X" then (parseHex (t.toList.drop 3)).map (- ·)
  else t.toInt?

/-- Each required component must be present and at least its minimum SVN; component-wise,
never lexicographic. One reason per failing component, in the (sorted) order of `minimum`. -/
def checkMinTcb (tcb : List (String × Int)) (minimum : List (String × Int)) (pre : String) : List String :=
  minimum.flatMap fun (comp, need) =>
    match tcb.lookup comp with
    | none => [s!"{pre}: tcb component '{comp}' missing"]
    | some got => if got < need then [s!"{pre}: tcb '{comp}'={got} < required {need}"] else []

def freshness (c : Claims) (p : Policy) (now : Int) (pre : String) : List String :=
  if c.issuedAt > now + p.clockSkewS then [s!"{pre}: evidence issued in the future"]
  else if now - c.issuedAt > p.maxAgeS then [s!"{pre}: evidence older than {p.maxAgeS}s"]
  else []

def guestPolicyReasons (p : Policy) (cpu : Claims) : List String :=
  if p.allowedGuestPolicy.isEmpty then [] else
  match cpu.extra.lookup "guest_policy" with
  | none => ["cpu: guest policy not reported"]
  | some gp =>
    match parseIntBase0 gp with
    | some v => if p.allowedGuestPolicy.contains v then [] else [s!"cpu: guest policy {gp} not in allow-list"]
    | none => [s!"cpu: guest policy {gp} not in allow-list"]

def cpuReasons (p : Policy) (cpu : Claims) (now : Int) : List String :=
  (if p.allowedCpuPlatforms.contains cpu.platform then [] else [s!"cpu: platform {cpu.platform} not allowed"]) ++
  (if cpu.debug && !p.allowDebug then ["cpu: debug mode enabled"] else []) ++
  (if p.allowedMeasurements.contains (lower cpu.measurement) then [] else ["cpu: measurement not in allow-list"]) ++
  checkMinTcb cpu.tcb p.minTcb "cpu" ++
  freshness cpu p now "cpu" ++
  guestPolicyReasons p cpu

def startsOk : Option String → Bool
  | some s => s.startsWith "ok:"
  | none => false

def orUnchecked : Option String → String
  | some s => s
  | none => "unchecked"

def gpuReasons (p : Policy) (i : Nat) (g : Claims) (now : Int) : List String :=
  let pre := s!"gpu[{i}]"
  (if p.allowedGpuPlatforms.contains g.platform then [] else [s!"{pre}: platform {g.platform} not allowed"]) ++
  (if g.debug && !p.allowDebug then [s!"{pre}: debug mode enabled"] else []) ++
  (if p.allowedGpuMeasurements.isEmpty || p.allowedGpuMeasurements.contains (lower g.measurement) then []
   else [s!"{pre}: measurement not in allow-list"]) ++
  checkMinTcb g.tcb p.minGpuTcb pre ++
  (if p.requireGpuRim && !(startsOk (g.extra.lookup "rim_driver") && startsOk (g.extra.lookup "rim_vbios"))
   then [s!"{pre}: reference manifests not verified (driver {orUnchecked (g.extra.lookup "rim_driver")}, vbios {orUnchecked (g.extra.lookup "rim_vbios")})"]
   else []) ++
  (if p.requireGpuOcsp && g.extra.lookup "ocsp" != some "good" then [s!"{pre}: certificate revocation not checked"] else []) ++
  freshness g p now pre

def noGpuReasons (p : Policy) (c : CompositeClaims) : List String :=
  if p.requireGpu && c.gpus.isEmpty then ["gpu: GPU evidence required but none presented"] else []

def allGpuReasons (p : Policy) (c : CompositeClaims) (now : Int) : List String :=
  c.gpus.zipIdx.flatMap fun (g, i) => gpuReasons p i g now

/-- The decision: every failing rule contributes a reason; allow iff none. -/
def evaluate (p : Policy) (c : CompositeClaims) (now : Int) : Decision :=
  let reasons := cpuReasons p c.cpu now ++ noGpuReasons p c ++ allGpuReasons p c now
  { allow := reasons.isEmpty, reasons := reasons }

end AttestRAG
