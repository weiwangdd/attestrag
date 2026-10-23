import AttestRAG.Binding
import AttestRAG.Policy

/-!
# Key release

Mirrors `ReferenceKBS.request_key` (`attestrag/kbs_client/reference_kbs.py`) together
with the checks it delegates to `CompositeVerifier.verify` (`attestrag/attest/base.py`):

1. the nonce is known and unexpired (and is consumed, even on failure);
2. the key id is known;
3. every report's signature / certificate chain verifies (opaque here: `sigsOk`);
4. the primary report comes from a CPU TEE, every GPU slot from a GPU;
5. CPU `report_data = cpu_report_data(nonce, tee_pubkey)`;
6. each GPU `report_data = gpu_report_data(cpu.report_data)`;
7. `evaluate(policy, claims, now).allow`.

The key is wrapped to `tee_pubkey` only if all of them hold.

`release_iff` states that `release` is exactly the conjunction of these conditions,
so any single failure means no key. `release_pins_session` and `gpu_not_replayable`
use the hash assumption to show what an accepted request commits to.
-/

namespace AttestRAG

/-- One `request_key` call, after the KBS has looked up its own state. -/
structure Request where
  /-- `nonce` was issued by `challenge()`, not yet consumed, and `now ≤ expiry`. -/
  nonceLive : Bool
  keyKnown : Bool
  /-- All signatures and certificate chains verified (`Verifier.verify` did not raise
  for a cryptographic reason). Crypto is outside this model. -/
  sigsOk : Bool
  nonce : Bytes
  teePubkey : Bytes
  claims : CompositeClaims

/-- Check 4: `CompositeVerifier` rejects a GPU as primary and a CPU in a GPU slot. -/
def slotsOk (cc : CompositeClaims) : Bool :=
  !cc.cpu.platform.isGpu && cc.gpus.all (·.platform.isGpu)

/-- Checks 5 and 6. -/
def bindingOk (H : HashModel) (nonce pk : Bytes) (cc : CompositeClaims) : Bool :=
  cc.cpu.reportData == cpuReportData H nonce pk &&
  cc.gpus.all (·.reportData == gpuReportData H cc.cpu.reportData)

/-- The release decision of `request_key`: `true` iff the wrapped key is returned. -/
def release (H : HashModel) (p : Policy) (r : Request) (now : Int) : Bool :=
  r.nonceLive && r.keyKnown && r.sigsOk && slotsOk r.claims &&
  bindingOk H r.nonce r.teePubkey r.claims && evaluate p r.claims now

/-- Declarative binding conditions. -/
def Bound (H : HashModel) (nonce pk : Bytes) (cc : CompositeClaims) : Prop :=
  cc.cpu.reportData = cpuReportData H nonce pk ∧
  ∀ g ∈ cc.gpus, g.reportData = gpuReportData H cc.cpu.reportData

/-- Every condition for releasing a key. -/
def MayRelease (H : HashModel) (p : Policy) (r : Request) (now : Int) : Prop :=
  r.nonceLive = true ∧ r.keyKnown = true ∧ r.sigsOk = true ∧
  r.claims.cpu.platform.isGpu = false ∧ (∀ g ∈ r.claims.gpus, g.platform.isGpu = true) ∧
  Bound H r.nonce r.teePubkey r.claims ∧
  Admissible p r.claims now

theorem bindingOk_iff (H : HashModel) (nonce pk : Bytes) (cc : CompositeClaims) :
    bindingOk H nonce pk cc = true ↔ Bound H nonce pk cc := by
  simp [bindingOk, Bound]

/-- **Main theorem.** A key is released iff every condition holds. -/
theorem release_iff (H : HashModel) (p : Policy) (r : Request) (now : Int) :
    release H p r now = true ↔ MayRelease H p r now := by
  simp only [release, MayRelease, slotsOk, Bool.and_eq_true, bindingOk_iff, evaluate_iff,
    Bool.not_eq_eq_eq_not, Bool.not_true, List.all_eq_true, and_assoc]

/-! ## Any failed condition: no key -/

section Deny
variable {H : HashModel} {p : Policy} {r : Request} {now : Int}

theorem no_release_of_not (h : ¬ MayRelease H p r now) : release H p r now = false := by
  cases hr : release H p r now
  · rfl
  · exact absurd ((release_iff H p r now).1 hr) h

theorem no_release_of_dead_nonce (h : r.nonceLive = false) : release H p r now = false :=
  no_release_of_not fun hm => by simp_all [MayRelease]

theorem no_release_of_unknown_key (h : r.keyKnown = false) : release H p r now = false :=
  no_release_of_not fun hm => by simp_all [MayRelease]

theorem no_release_of_bad_signature (h : r.sigsOk = false) : release H p r now = false :=
  no_release_of_not fun hm => by simp_all [MayRelease]

/-- CPU report not bound to this session's nonce and public key. -/
theorem no_release_of_cpu_unbound
    (h : r.claims.cpu.reportData ≠ cpuReportData H r.nonce r.teePubkey) :
    release H p r now = false :=
  no_release_of_not fun ⟨_, _, _, _, _, ⟨hb, _⟩, _⟩ => h hb

/-- Some GPU report not bound to the CPU report's report_data. -/
theorem no_release_of_gpu_unbound (g : Claims) (hg : g ∈ r.claims.gpus)
    (h : g.reportData ≠ gpuReportData H r.claims.cpu.reportData) :
    release H p r now = false :=
  no_release_of_not fun ⟨_, _, _, _, _, ⟨_, hb⟩, _⟩ => h (hb g hg)

/-- A policy rule fails (any of the `evaluate_false_of_*` conditions). -/
theorem no_release_of_policy (h : evaluate p r.claims now = false) :
    release H p r now = false := by
  simp [release, h]

theorem no_release_of_cpu_tcb_below {comp : String} {need got : Nat}
    (hm : (comp, need) ∈ p.minTcb) (hl : r.claims.cpu.tcb.lookup comp = some got)
    (hlt : got < need) : release H p r now = false :=
  no_release_of_policy (evaluate_false_of_cpu_tcb_below hm hl hlt)

theorem no_release_of_cpu_tcb_missing {comp : String} {need : Nat}
    (hm : (comp, need) ∈ p.minTcb) (hl : r.claims.cpu.tcb.lookup comp = none) :
    release H p r now = false :=
  no_release_of_policy (evaluate_false_of_cpu_tcb_missing hm hl)

theorem no_release_of_gpu_tcb (g : Claims) (hg : g ∈ r.claims.gpus)
    (h : ¬ TcbOk g.tcb p.minGpuTcb) : release H p r now = false :=
  no_release_of_policy (evaluate_false_of_gpu_tcb g hg h)

end Deny

/-! ## What an accepted request commits to (needs the hash assumption) -/

section Binding
variable {H : HashModel} {p : Policy} {now : Int}

/-- An accepted CPU report fixes the nonce and the public key the key is wrapped to:
the same report cannot be accepted for another nonce or for another key. -/
theorem release_pins_session (hH : CollisionFree H) {r r' : Request} {now' : Int}
    (h : release H p r now = true) (h' : release H p r' now' = true)
    (hcpu : r'.claims.cpu.reportData = r.claims.cpu.reportData) :
    r'.nonce = r.nonce ∧ r'.teePubkey = r.teePubkey := by
  obtain ⟨_, _, _, _, _, ⟨hb, _⟩, _⟩ := (release_iff H p r now).1 h
  obtain ⟨_, _, _, _, _, ⟨hb', _⟩, _⟩ := (release_iff H p r' now').1 h'
  exact cpuReportData_inj hH (hb' ▸ hcpu ▸ hb)

/-- GPU evidence from one accepted session cannot be accepted in a session with a
different CPU report: replaying or splicing a GPU report across sessions fails. -/
theorem gpu_not_replayable (hH : CollisionFree H) {r r' : Request} {now' : Int} {g : Claims}
    (h : release H p r now = true) (h' : release H p r' now' = true)
    (hg : g ∈ r.claims.gpus) (hg' : g ∈ r'.claims.gpus) :
    r'.claims.cpu.reportData = r.claims.cpu.reportData := by
  obtain ⟨_, _, _, _, _, ⟨_, hb⟩, _⟩ := (release_iff H p r now).1 h
  obtain ⟨_, _, _, _, _, ⟨_, hb'⟩, _⟩ := (release_iff H p r' now').1 h'
  exact gpuReportData_inj hH ((hb' g hg').symm.trans (hb g hg))

/-- Combining both: a GPU report accepted in two sessions forces the same nonce and
public key, so a GPU report is good for exactly one session. -/
theorem gpu_pins_session (hH : CollisionFree H) {r r' : Request} {now' : Int} {g : Claims}
    (h : release H p r now = true) (h' : release H p r' now' = true)
    (hg : g ∈ r.claims.gpus) (hg' : g ∈ r'.claims.gpus) :
    r'.nonce = r.nonce ∧ r'.teePubkey = r.teePubkey :=
  release_pins_session hH h h' (gpu_not_replayable hH h h' hg hg')

end Binding

/-! ## Single-use nonces

`request_key` pops the nonce before any other check (`self._nonces.pop(nonce, None)`),
so a nonce is consumed whether or not the key is released. -/

structure KbsState where
  /-- `_nonces`: nonce ↦ expiry. -/
  nonces : List (Bytes × Int)
  keyIds : List String

def KbsState.nonceLive (st : KbsState) (nonce : Bytes) (now : Int) : Bool :=
  match st.nonces.lookup nonce with
  | some expiry => decide (now ≤ expiry)
  | none => false

/-- `request_key`: returns the new state and whether the key was released. -/
def requestKey (H : HashModel) (p : Policy) (st : KbsState) (keyId : String)
    (sigsOk : Bool) (nonce pk : Bytes) (cc : CompositeClaims) (now : Int) : KbsState × Bool :=
  let st' := { st with nonces := st.nonces.filter (·.1 != nonce) }
  let r : Request := { nonceLive := st.nonceLive nonce now, keyKnown := keyId ∈ st.keyIds,
                       sigsOk, nonce, teePubkey := pk, claims := cc }
  (st', release H p r now)

theorem lookup_filter_self (l : List (Bytes × Int)) (k : Bytes) :
    (l.filter (·.1 != k)).lookup k = none := by
  simp only [List.lookup_eq_none_iff, List.mem_filter, bne_iff_ne]
  intro a h hk
  exact h.2 hk.symm

/-- A nonce is consumed by its first use, whatever the outcome: replaying the same
nonce in the next request never releases a key. -/
theorem nonce_single_use (H : HashModel) (p : Policy) (st : KbsState)
    (k₁ k₂ : String) (s₁ s₂ : Bool) (nonce pk₁ pk₂ : Bytes)
    (cc₁ cc₂ : CompositeClaims) (t₁ t₂ : Int) :
    (requestKey H p (requestKey H p st k₁ s₁ nonce pk₁ cc₁ t₁).1 k₂ s₂ nonce pk₂ cc₂ t₂).2
      = false := by
  apply no_release_of_dead_nonce
  simp [requestKey, KbsState.nonceLive, lookup_filter_self]

end AttestRAG
