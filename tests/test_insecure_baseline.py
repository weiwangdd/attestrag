"""The insecure-baseline mode is deterministic across processes and clearly separated from real platforms."""

import hashlib
import time
from pathlib import Path

import pytest

from attestrag.attest import AttestationError, CompositeAttester, CompositeClaims, CompositeEvidence, CompositeVerifier, Platform
from attestrag.attest.mock import INSECURE_BASELINE_MEASUREMENT, MockVendor, insecure_baseline_attester, insecure_baseline_verifier
from attestrag.policy import Policy, evaluate

POLICY = Path(__file__).parent.parent / "policies" / "insecure-baseline.json"


def test_seeded_vendor_is_deterministic_and_seed_specific():
    a, b = MockVendor("x", seed=b"one"), MockVendor("x", seed=b"one")
    assert a.root_public == b.root_public and a.root_public != MockVendor("x", seed=b"two").root_public
    assert MockVendor("x").root_public != MockVendor("x").root_public  # unseeded stays random


def test_baseline_round_trip_and_policy():
    rd = hashlib.sha384(b"session").digest()
    ev = CompositeAttester(insecure_baseline_attester()).attest(rd)
    cc = CompositeVerifier({Platform.MOCK_CPU: insecure_baseline_verifier()}).verify(ev, rd)
    assert cc.cpu.platform == Platform.MOCK_CPU and cc.cpu.measurement == INSECURE_BASELINE_MEASUREMENT
    pol = Policy.from_json(POLICY.read_text())
    now = time.time()
    assert evaluate(pol, cc, now).allow
    # the real policy never accepts it, and a verifier without the mock root never verifies it
    real = Policy.from_json((POLICY.parent / "h200-genoa.json").read_text())
    assert not evaluate(real, cc, now).allow
    with pytest.raises(AttestationError):
        CompositeVerifier({}).verify(ev, rd)
