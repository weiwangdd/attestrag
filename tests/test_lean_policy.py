"""Differential test: the Python policy engine against the Lean executable specification.

formal/lean builds `attestrag_policy`, a binary that reads {policy, claims, now} as JSON and prints
the decision. Every case here is evaluated by both and must agree on `allow` and on the exact
reason strings. Skipped when the binary is not built (`cd formal/lean && lake build`).
"""

import json
import random
import subprocess
from pathlib import Path

import pytest

from attestrag.attest import CompositeClaims, Platform
from attestrag.attest.types import Claims
from attestrag.policy import Policy, evaluate

ROOT = Path(__file__).parent.parent
BIN = ROOT / "formal" / "lean" / ".lake" / "build" / "bin" / "attestrag_policy"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="Lean binary not built (cd formal/lean && lake build)")

PLATFORMS = ["sev-snp", "tdx", "nvidia-cc", "mock-cpu", "mock-gpu"]
COMPONENTS = ["bootloader", "tee", "snp", "microcode", "fw", "boot"]
MEAS = ["aa" * 48, "bb" * 48, "AA" * 48, "cafe" * 24, "00" * 48]


def claims_json(c: Claims) -> dict:
    return {"platform": c.platform.value, "measurement": c.measurement, "tcb": c.tcb, "debug": c.debug,
            "issued_at": int(c.issued_at), "extra": {k: str(v) for k, v in c.extra.items()}}


def lean_decide(policy: dict, claims: CompositeClaims, now: int) -> dict:
    payload = {"policy": policy, "claims": {"cpu": claims_json(claims.cpu), "gpus": [claims_json(g) for g in claims.gpus]}, "now": now}
    r = subprocess.run([str(BIN)], input=json.dumps(payload), capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def python_decide(policy: dict, claims: CompositeClaims, now: int) -> dict:
    d = evaluate(Policy.from_dict(policy), claims, float(now))
    return {"allow": d.allow, "reasons": list(d.reasons)}


def rand_claims(rng: random.Random, gpu: bool, now: int) -> Claims:
    extra = {}
    if rng.random() < 0.7:
        extra["guest_policy"] = rng.choice(["0x30000", "0x20000", "196608", "0X30000"])
    if gpu:
        if rng.random() < 0.6:
            extra["rim_driver"] = rng.choice(["ok:NV_GPU_DRIVER_GH100_580.178.04", "not-found:NV_GPU_DRIVER_X", "ok:x"])
        if rng.random() < 0.6:
            extra["rim_vbios"] = rng.choice(["ok:NV_GPU_VBIOS_1010_0230_894_9600B70002", "not-found:NV_GPU_VBIOS_Y"])
        if rng.random() < 0.6:
            extra["ocsp"] = rng.choice(["good", "unknown", "revoked"])
    return Claims(
        platform=Platform(rng.choice(["nvidia-cc", "mock-gpu"] if gpu else ["sev-snp", "tdx", "mock-cpu"])),
        measurement=rng.choice(MEAS),
        tcb={k: rng.randint(0, 100) for k in rng.sample(COMPONENTS, rng.randint(0, 4))} if not gpu or rng.random() < 0.5 else {},
        debug=rng.random() < 0.2,
        issued_at=float(now + rng.choice([0, -1, -10, -299, -301, -5000, 29, 31, 400])),
        extra=extra,
        report_data=b"",
        signer="t",
    )


def rand_policy(rng: random.Random) -> dict:
    d = {
        "allowed_cpu_platforms": rng.sample(["sev-snp", "tdx", "mock-cpu"], rng.randint(1, 3)),
        "allowed_measurements": rng.sample(MEAS, rng.randint(0, 3)),
        "min_tcb": {k: rng.randint(0, 100) for k in rng.sample(COMPONENTS, rng.randint(0, 4))},
        "allow_debug": rng.random() < 0.3,
        "max_age_s": rng.choice([300, 60, 10000]),
        "clock_skew_s": rng.choice([30, 0, 100]),
        "require_gpu": rng.random() < 0.5,
        "allowed_gpu_platforms": rng.sample(["nvidia-cc", "mock-gpu"], rng.randint(0, 2)),
        "allowed_gpu_measurements": rng.sample(MEAS, rng.randint(0, 2)),
        "min_gpu_tcb": {k: rng.randint(0, 100) for k in rng.sample(COMPONENTS, rng.randint(0, 2))},
        "require_gpu_rim": rng.random() < 0.4,
        "require_gpu_ocsp": rng.random() < 0.4,
        "allowed_guest_policy": rng.choice([[], ["0x30000"], ["0x30000", 131072], [196608]]),
    }
    return d


@pytest.mark.parametrize("seed", range(5))
def test_random_cases_agree(seed):
    rng = random.Random(seed)
    now = 1792800000
    mismatches = []
    for _ in range(100):
        pol = rand_policy(rng)
        cc = CompositeClaims(rand_claims(rng, False, now), tuple(rand_claims(rng, True, now) for _ in range(rng.randint(0, 2))))
        py, lean = python_decide(pol, cc, now), lean_decide(pol, cc, now)
        if py != lean:
            mismatches.append((pol, cc, py, lean))
    assert not mismatches, f"{len(mismatches)} disagreements, first: {mismatches[0]}"


def test_real_h200_policy_and_claims_agree():
    """The published policy against the verified composite claims of the h200 fixture, plus variations."""
    from tests.test_composite_h200 import pair  # noqa: F401  (fixture function reused directly)
    import tests.test_composite_h200 as comp
    meta = json.loads((comp.FIX / "meta.json").read_text())
    _, snp_ev, gpu_ev, cv = comp.pair.__wrapped__()
    from attestrag.attest import CompositeEvidence
    cc = cv.verify(CompositeEvidence(snp_ev, (gpu_ev,)), bytes.fromhex(meta["report_data"]))
    pol = json.loads((ROOT / "policies" / "h200-genoa.json").read_text())
    now = int(meta["verify_at"])
    assert python_decide(pol, cc, now) == lean_decide(pol, cc, now) and python_decide(pol, cc, now)["allow"]
    for change in ({"require_gpu_rim": True}, {"min_tcb": {**pol["min_tcb"], "snp": 25}}, {"allowed_guest_policy": ["0x20000"]},
                   {"allowed_measurements": ["00" * 48]}, {"allowed_gpu_measurements": ["11" * 48]}, {"require_gpu_ocsp": False}):
        p2 = {**pol, **change}
        assert python_decide(p2, cc, now) == lean_decide(p2, cc, now), change
    assert python_decide(pol, CompositeClaims(cc.cpu), now) == lean_decide(pol, CompositeClaims(cc.cpu), now)
