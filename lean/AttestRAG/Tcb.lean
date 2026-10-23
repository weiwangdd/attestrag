import AttestRAG.Types

/-!
# Component-wise minimum TCB

Mirrors `attestrag.policy.engine.check_min_tcb`. Every component named in the
minimum must be present in the reported TCB with an SVN at least the minimum.
The comparison is per component, not lexicographic: a newer value in one component
never compensates for an older value in another (`no_compensation`).
-/

namespace AttestRAG

/-- Which report a reason is about: `"cpu"` or `"gpu[i]"` in Python. -/
inductive Subject where
  | cpu
  | gpu (i : Nat)
  deriving DecidableEq, Repr

/-- The reasons `evaluate` can give. Python renders each of these as a string;
the constructor ↔ message mapping is in `docs/lean-correspondence.md`. -/
inductive Reason where
  | platformNotAllowed (s : Subject) (p : Platform)
  | debugEnabled (s : Subject)
  | measurementNotAllowed (s : Subject)
  | tcbMissing (s : Subject) (comp : String)
  | tcbTooLow (s : Subject) (comp : String) (got need : Nat)
  | issuedInFuture (s : Subject)
  | tooOld (s : Subject)
  | guestPolicyMissing
  | guestPolicyNotAllowed (gp : Nat)
  | gpuRequired
  deriving DecidableEq, Repr

/-- Reasons for one minimum-TCB entry. -/
def tcbEntryReasons (s : Subject) (tcb : Tcb) (entry : String × Nat) : List Reason :=
  match tcb.lookup entry.1 with
  | none => [.tcbMissing s entry.1]
  | some got => if got < entry.2 then [.tcbTooLow s entry.1 got entry.2] else []

/-- `check_min_tcb(tcb, minimum, prefix)`. Python iterates `sorted(minimum.items())`;
the order only affects the order of reasons, never whether the list is empty. -/
def tcbReasons (s : Subject) (tcb minimum : Tcb) : List Reason :=
  minimum.flatMap (tcbEntryReasons s tcb)

/-- Declarative meaning of "the TCB meets the minimum". -/
def TcbOk (tcb minimum : Tcb) : Prop :=
  ∀ comp need, (comp, need) ∈ minimum → ∃ got, tcb.lookup comp = some got ∧ need ≤ got

theorem tcbEntryReasons_eq_nil (s : Subject) (tcb : Tcb) (comp : String) (need : Nat) :
    tcbEntryReasons s tcb (comp, need) = [] ↔
      ∃ got, tcb.lookup comp = some got ∧ need ≤ got := by
  unfold tcbEntryReasons
  cases h : tcb.lookup comp with
  | none => simp
  | some got =>
    by_cases hl : got < need
    · simp [hl]
    · simp [hl]
      omega

/-- `check_min_tcb` returns no reasons exactly when the TCB meets the minimum. -/
theorem tcbReasons_eq_nil (s : Subject) (tcb minimum : Tcb) :
    tcbReasons s tcb minimum = [] ↔ TcbOk tcb minimum := by
  unfold tcbReasons TcbOk
  rw [List.flatMap_eq_nil_iff]
  constructor
  · intro h comp need hm
    exact (tcbEntryReasons_eq_nil s tcb comp need).1 (h _ hm)
  · intro h ⟨comp, need⟩ hm
    exact (tcbEntryReasons_eq_nil s tcb comp need).2 (h comp need hm)

/-- A required component that is missing fails the check. -/
theorem not_tcbOk_of_missing {tcb minimum : Tcb} {comp : String} {need : Nat}
    (hm : (comp, need) ∈ minimum) (hl : tcb.lookup comp = none) : ¬ TcbOk tcb minimum := by
  intro h
  obtain ⟨_, hs, _⟩ := h comp need hm
  simp_all

/-- A required component below its minimum fails the check, whatever the other
components are. -/
theorem not_tcbOk_of_below {tcb minimum : Tcb} {comp : String} {need got : Nat}
    (hm : (comp, need) ∈ minimum) (hl : tcb.lookup comp = some got) (hlt : got < need) :
    ¬ TcbOk tcb minimum := by
  intro h
  obtain ⟨h', hs, hle⟩ := h comp need hm
  rw [hl] at hs
  cases hs
  omega

/-- `tcb'` dominates `tcb` component-wise. -/
def Dominates (tcb' tcb : Tcb) : Prop :=
  ∀ comp got, tcb.lookup comp = some got → ∃ got', tcb'.lookup comp = some got' ∧ got ≤ got'

/-- Upgrading components never turns a passing TCB into a failing one. -/
theorem TcbOk.mono {tcb tcb' minimum : Tcb} (h : TcbOk tcb minimum) (hd : Dominates tcb' tcb) :
    TcbOk tcb' minimum := by
  intro comp need hm
  obtain ⟨got, hs, hle⟩ := h comp need hm
  obtain ⟨got', hs', hle'⟩ := hd comp got hs
  exact ⟨got', hs', Nat.le_trans hle hle'⟩

/-- The example from `tests/test_policy.py::test_tcb_is_componentwise_not_lexicographic`:
microcode 200 does not compensate for bootloader 2 < 3. -/
theorem no_compensation :
    ¬ TcbOk [("bootloader", 2), ("microcode", 200)] [("bootloader", 3), ("microcode", 115)] :=
  not_tcbOk_of_below (comp := "bootloader") (need := 3) (got := 2)
    (by simp) (by decide) (by decide)

end AttestRAG
