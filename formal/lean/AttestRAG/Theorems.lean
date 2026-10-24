import AttestRAG.Policy

/-! Properties of the executable specification. Core Lean only (no Mathlib). -/
namespace AttestRAG

/-- `allow` is exactly "no reason". -/
theorem allow_iff_no_reasons (p : Policy) (c : CompositeClaims) (now : Int) :
    (evaluate p c now).allow = true ↔ (evaluate p c now).reasons = [] := by
  simp [evaluate]

/-- Any reason denies. -/
theorem deny_of_mem_reasons (p : Policy) (c : CompositeClaims) (now : Int) (r : String)
    (h : r ∈ (evaluate p c now).reasons) : (evaluate p c now).allow = false := by
  cases hA : (evaluate p c now).allow with
  | false => rfl
  | true =>
    have := (allow_iff_no_reasons p c now).mp hA
    rw [this] at h
    exact absurd h List.not_mem_nil

/-- Where the CPU rules sit inside the decision. -/
theorem mem_reasons_of_mem_cpuReasons (p : Policy) (c : CompositeClaims) (now : Int) (r : String)
    (h : r ∈ cpuReasons p c.cpu now) : r ∈ (evaluate p c now).reasons := by
  simp only [evaluate, List.mem_append]
  exact Or.inl (Or.inl h)

theorem mem_cpuReasons_of_mem_checkMinTcb (p : Policy) (cpu : Claims) (now : Int) (r : String)
    (h : r ∈ checkMinTcb cpu.tcb p.minTcb "cpu") : r ∈ cpuReasons p cpu now := by
  simp only [cpuReasons, List.mem_append]
  exact Or.inl (Or.inl (Or.inr h))

/-- Debug mode on the CPU TEE is denied unless the policy allows it. -/
theorem deny_of_cpu_debug (p : Policy) (c : CompositeClaims) (now : Int)
    (hd : c.cpu.debug = true) (ha : p.allowDebug = false) : (evaluate p c now).allow = false := by
  apply deny_of_mem_reasons p c now "cpu: debug mode enabled"
  simp [evaluate, cpuReasons, hd, ha]

/-- A measurement outside the allow-list is denied, whatever else holds. -/
theorem deny_of_cpu_measurement (p : Policy) (c : CompositeClaims) (now : Int)
    (hm : lower c.cpu.measurement ∉ p.allowedMeasurements) : (evaluate p c now).allow = false := by
  apply deny_of_mem_reasons p c now "cpu: measurement not in allow-list"
  simp [evaluate, cpuReasons, hm]

/-- Requiring a GPU with none presented is denied. -/
theorem deny_of_missing_gpu (p : Policy) (c : CompositeClaims) (now : Int)
    (hr : p.requireGpu = true) (hg : c.gpus = []) : (evaluate p c now).allow = false := by
  apply deny_of_mem_reasons p c now "gpu: GPU evidence required but none presented"
  simp [evaluate, noGpuReasons, hr, hg]

/-- Component-wise TCB: a component below its minimum yields its reason, whatever the others are. -/
theorem checkMinTcb_mem_of_short (tcb minimum : List (String × Int)) (pre comp : String) (need got : Int)
    (hmin : (comp, need) ∈ minimum) (hlk : tcb.lookup comp = some got) (hlt : got < need) :
    s!"{pre}: tcb '{comp}'={got} < required {need}" ∈ checkMinTcb tcb minimum pre := by
  simp only [checkMinTcb, List.mem_flatMap]
  exact ⟨(comp, need), hmin, by simp [hlk, hlt]⟩

theorem checkMinTcb_mem_of_missing (tcb minimum : List (String × Int)) (pre comp : String) (need : Int)
    (hmin : (comp, need) ∈ minimum) (hlk : tcb.lookup comp = none) :
    s!"{pre}: tcb component '{comp}' missing" ∈ checkMinTcb tcb minimum pre := by
  simp only [checkMinTcb, List.mem_flatMap]
  exact ⟨(comp, need), hmin, by simp [hlk]⟩

/-- One TCB component below its minimum denies: SVNs are compared component-wise, never as a whole. -/
theorem deny_of_cpu_tcb_short (p : Policy) (c : CompositeClaims) (now : Int) (comp : String) (need got : Int)
    (hmin : (comp, need) ∈ p.minTcb) (hlk : c.cpu.tcb.lookup comp = some got) (hlt : got < need) :
    (evaluate p c now).allow = false :=
  deny_of_mem_reasons p c now _ (mem_reasons_of_mem_cpuReasons p c now _
    (mem_cpuReasons_of_mem_checkMinTcb p c.cpu now _
      (checkMinTcb_mem_of_short c.cpu.tcb p.minTcb "cpu" comp need got hmin hlk hlt)))

/-- A required component the report does not carry denies. -/
theorem deny_of_cpu_tcb_missing (p : Policy) (c : CompositeClaims) (now : Int) (comp : String) (need : Int)
    (hmin : (comp, need) ∈ p.minTcb) (hlk : c.cpu.tcb.lookup comp = none) :
    (evaluate p c now).allow = false :=
  deny_of_mem_reasons p c now _ (mem_reasons_of_mem_cpuReasons p c now _
    (mem_cpuReasons_of_mem_checkMinTcb p c.cpu now _
      (checkMinTcb_mem_of_missing c.cpu.tcb p.minTcb "cpu" comp need hmin hlk)))

/-- Enlarging the measurement allow-list never turns an allow into a deny. -/
theorem allow_mono_measurements (p : Policy) (c : CompositeClaims) (now : Int) (more : List String)
    (h : (evaluate p c now).allow = true) :
    (evaluate { p with allowedMeasurements := p.allowedMeasurements ++ more } c now).allow = true := by
  rw [allow_iff_no_reasons] at h ⊢
  simp only [evaluate, List.append_eq_nil_iff] at h ⊢
  obtain ⟨⟨hc, hn⟩, hg⟩ := h
  refine ⟨⟨?_, hn⟩, hg⟩
  simp only [cpuReasons, List.append_eq_nil_iff] at hc ⊢
  obtain ⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩ := hc
  refine ⟨⟨⟨⟨⟨h1, h2⟩, ?_⟩, h4⟩, h5⟩, h6⟩
  by_cases hm : lower c.cpu.measurement ∈ p.allowedMeasurements
  · simp [hm]
  · simp [hm] at h3

end AttestRAG
