import Lean
import AttestRAG.Policy
open Lean AttestRAG

/-! stdin: {"policy": <policy JSON as in policies/*.json>, "claims": {"cpu": C, "gpus": [C...]}, "now": int}
    where C = {"platform","measurement","tcb":{comp:int},"debug","issued_at":int,"extra":{k:str}}.
    stdout: {"allow": bool, "reasons": [str]} -/

def strs (j : Json) (k : String) : List String :=
  match j.getObjVal? k with
  | .ok (.arr a) => a.toList.filterMap fun v => (v.getStr?).toOption
  | _ => []

/-- JSON numbers are mantissa * 10^-exponent; accept integral values only (300 and 300.0, not 300.5). -/
def intOf' (j : Json) : Option Int :=
  match j with
  | .num n =>
    let d : Int := (10 : Int) ^ n.exponent
    if n.mantissa % d == 0 then some (n.mantissa / d) else none
  | .str s => parseIntBase0 s
  | _ => none

def intField (j : Json) (k : String) (d : Int) : Int :=
  match j.getObjVal? k with
  | .ok v => (intOf' v).getD d
  | _ => d

def boolField (j : Json) (k : String) (d : Bool) : Bool :=
  match j.getObjVal? k with
  | .ok (.bool b) => b
  | _ => d

def intMap (j : Json) (k : String) : List (String × Int) :=
  match j.getObjVal? k with
  | .ok (.obj o) =>
    let l := o.toList.filterMap fun (key, v) => (intOf' v).map fun i => (key, i)
    l.mergeSort (fun a b => decide (a.1 ≤ b.1))
  | _ => []

def strMap (j : Json) (k : String) : List (String × String) :=
  match j.getObjVal? k with
  | .ok (.obj o) => o.toList.filterMap fun (key, v) => match v with
      | .str s => some (key, s)
      | .num n => some (key, toString n)
      | .bool b => some (key, toString b)
      | _ => none
  | _ => []

def strField (j : Json) (k : String) : String :=
  match j.getObjVal? k with
  | .ok (.str s) => s
  | _ => ""

def claimsOf (j : Json) : Claims :=
  { platform := strField j "platform", measurement := strField j "measurement", tcb := intMap j "tcb",
    debug := boolField j "debug" false, issuedAt := intField j "issued_at" 0, extra := strMap j "extra" }

def policyOf (j : Json) : Policy :=
  { allowedCpuPlatforms := strs j "allowed_cpu_platforms"
    allowedMeasurements := (strs j "allowed_measurements").map lower
    minTcb := intMap j "min_tcb"
    allowDebug := boolField j "allow_debug" false
    maxAgeS := intField j "max_age_s" 300
    clockSkewS := intField j "clock_skew_s" 30
    requireGpu := boolField j "require_gpu" false
    allowedGpuPlatforms := strs j "allowed_gpu_platforms"
    allowedGpuMeasurements := (strs j "allowed_gpu_measurements").map lower
    minGpuTcb := intMap j "min_gpu_tcb"
    requireGpuRim := boolField j "require_gpu_rim" false
    requireGpuOcsp := boolField j "require_gpu_ocsp" false
    allowedGuestPolicy := match j.getObjVal? "allowed_guest_policy" with
      | .ok (.arr a) => a.toList.filterMap intOf'
      | _ => [] }

def main : IO UInt32 := do
  let input ← (← IO.getStdin).readToEnd
  match Json.parse input with
  | .error e => IO.eprintln s!"bad json: {e}"; return 2
  | .ok j =>
    let p := policyOf ((j.getObjVal? "policy").toOption.getD Json.null)
    let cj := (j.getObjVal? "claims").toOption.getD Json.null
    let gpus := match cj.getObjVal? "gpus" with | .ok (.arr a) => a.toList.map claimsOf | _ => []
    let c : CompositeClaims := { cpu := claimsOf ((cj.getObjVal? "cpu").toOption.getD Json.null), gpus := gpus }
    let d := evaluate p c (intField j "now" 0)
    let out : Json := Json.mkObj [("allow", Json.bool d.allow), ("reasons", Json.arr (d.reasons.toArray.map Json.str))]
    IO.println out.compress
    return 0
