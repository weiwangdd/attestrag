import AttestRAG.Tcb

/-!
# Policy evaluation

`reasons` mirrors `attestrag.policy.engine.evaluate` rule by rule, and `evaluate`
is `reasons = []`, exactly as Python's `Decision(allow=not reasons, ...)`.

`Admissible` is the declarative specification: a conjunction of every condition,
written without reference to how `evaluate` computes. The main result,
`evaluate_iff`, says the executable rules allow exactly the admissible claims. Every
`evaluate_false_of_*` corollary below is the contrapositive for one condition.
-/

namespace AttestRAG

/-- `_freshness`: `issued_at > now + skew` → future; else `now - issued_at > max_age`
→ too old. -/
def freshReasons (p : Policy) (s : Subject) (c : Claims) (now : Int) : List Reason :=
  if c.issuedAt > now + p.clockSkew then [.issuedInFuture s]
  else if now - c.issuedAt > p.maxAge then [.tooOld s]
  else []

/-- The guest-policy block of `evaluate` (checked only when the allow-list is non-empty). -/
def guestPolicyReasons (p : Policy) (c : Claims) : List Reason :=
  if p.allowedGuestPolicy.isEmpty then []
  else match c.guestPolicy with
    | none => [.guestPolicyMissing]
    | some gp => if gp ∈ p.allowedGuestPolicy then [] else [.guestPolicyNotAllowed gp]

/-- CPU half of `evaluate`. -/
def cpuReasons (p : Policy) (c : Claims) (now : Int) : List Reason :=
  (if c.platform ∈ p.allowedCpuPlatforms then [] else [.platformNotAllowed .cpu c.platform]) ++
  (if c.debug && !p.allowDebug then [.debugEnabled .cpu] else []) ++
  (if c.measurement.toLower ∈ p.allowedMeasurements then [] else [.measurementNotAllowed .cpu]) ++
  tcbReasons .cpu c.tcb p.minTcb ++
  freshReasons p .cpu c now ++
  guestPolicyReasons p c

/-- Body of the `for i, g in enumerate(claims.gpus)` loop. -/
def gpuReasons (p : Policy) (i : Nat) (g : Claims) (now : Int) : List Reason :=
  let s := Subject.gpu i
  (if g.platform ∈ p.allowedGpuPlatforms then [] else [.platformNotAllowed s g.platform]) ++
  (if g.debug && !p.allowDebug then [.debugEnabled s] else []) ++
  (if !p.allowedGpuMeasurements.isEmpty && g.measurement.toLower ∉ p.allowedGpuMeasurements
    then [.measurementNotAllowed s] else []) ++
  tcbReasons s g.tcb p.minGpuTcb ++
  freshReasons p s g now

/-- The whole loop, `enumerate` starting at `i`. -/
def gpusReasons (p : Policy) (now : Int) : Nat → List Claims → List Reason
  | _, [] => []
  | i, g :: gs => gpuReasons p i g now ++ gpusReasons p now (i + 1) gs

/-- `evaluate(policy, claims, now).reasons` -/
def reasons (p : Policy) (cc : CompositeClaims) (now : Int) : List Reason :=
  cpuReasons p cc.cpu now ++
  (if p.requireGpu && cc.gpus.isEmpty then [.gpuRequired] else []) ++
  gpusReasons p now 0 cc.gpus

/-- `evaluate(policy, claims, now).allow` -/
def evaluate (p : Policy) (cc : CompositeClaims) (now : Int) : Bool :=
  (reasons p cc now).isEmpty

/-! ## Declarative specification -/

def Fresh (p : Policy) (c : Claims) (now : Int) : Prop :=
  c.issuedAt ≤ now + p.clockSkew ∧ now - c.issuedAt ≤ p.maxAge

def GuestPolicyOk (p : Policy) (c : Claims) : Prop :=
  p.allowedGuestPolicy ≠ [] → ∃ gp, c.guestPolicy = some gp ∧ gp ∈ p.allowedGuestPolicy

def CpuOk (p : Policy) (c : Claims) (now : Int) : Prop :=
  c.platform ∈ p.allowedCpuPlatforms ∧
  (c.debug = true → p.allowDebug = true) ∧
  c.measurement.toLower ∈ p.allowedMeasurements ∧
  TcbOk c.tcb p.minTcb ∧
  Fresh p c now ∧
  GuestPolicyOk p c

def GpuOk (p : Policy) (g : Claims) (now : Int) : Prop :=
  g.platform ∈ p.allowedGpuPlatforms ∧
  (g.debug = true → p.allowDebug = true) ∧
  (p.allowedGpuMeasurements ≠ [] → g.measurement.toLower ∈ p.allowedGpuMeasurements) ∧
  TcbOk g.tcb p.minGpuTcb ∧
  Fresh p g now

/-- Every condition the key-release policy imposes on verified claims. -/
def Admissible (p : Policy) (cc : CompositeClaims) (now : Int) : Prop :=
  CpuOk p cc.cpu now ∧
  (p.requireGpu = true → cc.gpus ≠ []) ∧
  ∀ g ∈ cc.gpus, GpuOk p g now

/-! ## Rules ↔ specification -/

theorem freshReasons_eq_nil (p : Policy) (s : Subject) (c : Claims) (now : Int) :
    freshReasons p s c now = [] ↔ Fresh p c now := by
  unfold freshReasons Fresh
  by_cases h1 : c.issuedAt > now + p.clockSkew
  · simp [h1]
    omega
  · by_cases h2 : now - c.issuedAt > p.maxAge
    · simp [h1, h2]
    · simp [h1, h2]
      omega

theorem guestPolicyReasons_eq_nil (p : Policy) (c : Claims) :
    guestPolicyReasons p c = [] ↔ GuestPolicyOk p c := by
  unfold guestPolicyReasons GuestPolicyOk
  by_cases he : p.allowedGuestPolicy = []
  · simp [he]
  · cases hg : c.guestPolicy with
    | none => simp [he, List.isEmpty_iff]
    | some gp =>
      by_cases hm : gp ∈ p.allowedGuestPolicy
      · simp [he, hm, List.isEmpty_iff]
      · simp [he, hm, List.isEmpty_iff]

theorem cpuReasons_eq_nil (p : Policy) (c : Claims) (now : Int) :
    cpuReasons p c now = [] ↔ CpuOk p c now := by
  unfold cpuReasons CpuOk
  simp only [List.append_eq_nil_iff, tcbReasons_eq_nil, freshReasons_eq_nil,
    guestPolicyReasons_eq_nil]
  cases c.debug <;> cases p.allowDebug <;> simp [and_assoc]

theorem gpuReasons_eq_nil (p : Policy) (i : Nat) (g : Claims) (now : Int) :
    gpuReasons p i g now = [] ↔ GpuOk p g now := by
  unfold gpuReasons GpuOk
  simp only [List.append_eq_nil_iff, tcbReasons_eq_nil, freshReasons_eq_nil]
  by_cases he : p.allowedGpuMeasurements = []
  · cases g.debug <;> cases p.allowDebug <;> simp [he, and_assoc]
  · by_cases hm : g.measurement.toLower ∈ p.allowedGpuMeasurements
    · cases g.debug <;> cases p.allowDebug <;> simp [he, hm, and_assoc]
    · cases g.debug <;> cases p.allowDebug <;> simp [he, hm]

theorem gpusReasons_eq_nil (p : Policy) (now : Int) (i : Nat) (gs : List Claims) :
    gpusReasons p now i gs = [] ↔ ∀ g ∈ gs, GpuOk p g now := by
  induction gs generalizing i with
  | nil => simp [gpusReasons]
  | cons g gs ih => simp [gpusReasons, gpuReasons_eq_nil, ih]

/-- **Main policy theorem.** The rules allow exactly the admissible claims. -/
theorem evaluate_iff (p : Policy) (cc : CompositeClaims) (now : Int) :
    evaluate p cc now = true ↔ Admissible p cc now := by
  unfold evaluate reasons Admissible
  rw [List.isEmpty_iff]
  simp only [List.append_eq_nil_iff, cpuReasons_eq_nil, gpusReasons_eq_nil]
  cases p.requireGpu <;> cases cc.gpus <;> simp

/-! ## Any failed condition denies -/

section Deny
variable {p : Policy} {cc : CompositeClaims} {now : Int}

theorem evaluate_false_of_not_admissible (h : ¬ Admissible p cc now) :
    evaluate p cc now = false := by
  cases he : evaluate p cc now
  · rfl
  · exact absurd ((evaluate_iff p cc now).1 he) h

theorem evaluate_false_of_cpu_platform (h : cc.cpu.platform ∉ p.allowedCpuPlatforms) :
    evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨⟨hp, _⟩, _⟩ => h hp

theorem evaluate_false_of_cpu_debug (hd : cc.cpu.debug = true) (ha : p.allowDebug = false) :
    evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨⟨_, hdbg, _⟩, _⟩ => by simp_all

theorem evaluate_false_of_cpu_measurement
    (h : cc.cpu.measurement.toLower ∉ p.allowedMeasurements) : evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨⟨_, _, hm, _⟩, _⟩ => h hm

theorem evaluate_false_of_cpu_tcb (h : ¬ TcbOk cc.cpu.tcb p.minTcb) :
    evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨⟨_, _, _, ht, _⟩, _⟩ => h ht

theorem evaluate_false_of_cpu_tcb_missing {comp : String} {need : Nat}
    (hm : (comp, need) ∈ p.minTcb) (hl : cc.cpu.tcb.lookup comp = none) :
    evaluate p cc now = false :=
  evaluate_false_of_cpu_tcb (not_tcbOk_of_missing hm hl)

theorem evaluate_false_of_cpu_tcb_below {comp : String} {need got : Nat}
    (hm : (comp, need) ∈ p.minTcb) (hl : cc.cpu.tcb.lookup comp = some got) (hlt : got < need) :
    evaluate p cc now = false :=
  evaluate_false_of_cpu_tcb (not_tcbOk_of_below hm hl hlt)

theorem evaluate_false_of_cpu_stale (h : ¬ Fresh p cc.cpu now) : evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨⟨_, _, _, _, hf, _⟩, _⟩ => h hf

theorem evaluate_false_of_guest_policy (h : ¬ GuestPolicyOk p cc.cpu) :
    evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨⟨_, _, _, _, _, hg⟩, _⟩ => h hg

theorem evaluate_false_of_gpu_missing (hr : p.requireGpu = true) (hg : cc.gpus = []) :
    evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨_, hreq, _⟩ => hreq hr hg

theorem evaluate_false_of_gpu (g : Claims) (hg : g ∈ cc.gpus) (h : ¬ GpuOk p g now) :
    evaluate p cc now = false :=
  evaluate_false_of_not_admissible fun ⟨_, _, hall⟩ => h (hall g hg)

theorem evaluate_false_of_gpu_tcb (g : Claims) (hg : g ∈ cc.gpus)
    (h : ¬ TcbOk g.tcb p.minGpuTcb) : evaluate p cc now = false :=
  evaluate_false_of_gpu g hg fun ⟨_, _, _, ht, _⟩ => h ht

end Deny

end AttestRAG
