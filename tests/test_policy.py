import time

from attestrag.attest import cpu_report_data
from attestrag.policy import Policy, check_min_tcb, evaluate

RD = cpu_report_data(b"n" * 32, b"k" * 32)


def claims(make_attester, verifier, **kw):
    return verifier.verify(make_attester(**kw).attest(RD), RD)


def test_good_claims_allowed(make_attester, verifier, policy):
    assert evaluate(policy, claims(make_attester, verifier), time.time()).allow


def test_unknown_measurement_denied(make_attester, verifier, policy):
    d = evaluate(policy, claims(make_attester, verifier, measurement="ff" * 48), time.time())
    assert not d.allow and any("measurement" in r for r in d.reasons)


def test_tcb_below_minimum_denied(make_attester, verifier, policy):
    tcb = {"bootloader": 3, "tee": 0, "snp": 7, "microcode": 115}
    d = evaluate(policy, claims(make_attester, verifier, tcb=tcb), time.time())
    assert not d.allow and any("'snp'=7 < required 8" in r for r in d.reasons)


def test_tcb_is_componentwise_not_lexicographic():
    # newer microcode must not compensate for an older bootloader
    assert check_min_tcb({"bootloader": 2, "microcode": 200}, {"bootloader": 3, "microcode": 115}, "x")
    assert check_min_tcb({"bootloader": 3}, {"bootloader": 3, "snp": 1}, "x")  # missing comp
    assert not check_min_tcb({"bootloader": 4, "snp": 9}, {"bootloader": 3, "snp": 8}, "x")


def test_debug_denied(make_attester, verifier, policy):
    assert not evaluate(policy, claims(make_attester, verifier, debug=True), time.time()).allow


def test_stale_evidence_denied(make_attester, verifier, policy):
    c = claims(make_attester, verifier)
    assert not evaluate(policy, c, time.time() + policy.max_age_s + 1).allow


def test_gpu_required(make_attester, verifier, policy):
    p = Policy(**{**policy.__dict__, "require_gpu": True})
    assert not evaluate(p, claims(make_attester, verifier), time.time()).allow
    assert evaluate(p, claims(make_attester, verifier, gpus=2), time.time()).allow
    old_driver = claims(make_attester, verifier, gpus=1, gpu_tcb={"vbios": 96, "driver": 470})
    d = evaluate(p, old_driver, time.time())
    assert not d.allow and any(r.startswith("gpu[0]: tcb 'driver'") for r in d.reasons)


def test_policy_from_json():
    p = Policy.from_json(
        '{"allowed_cpu_platforms": ["sev-snp", "tdx"], "allowed_measurements": ["AB"],'
        ' "min_tcb": {"snp": 22}}'
    )
    assert "ab" in p.allowed_measurements and p.min_tcb == {"snp": 22}
