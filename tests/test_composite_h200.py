"""Composite golden case: one bound pair of real evidence from the h200 guest.

tests/fixtures/composite/h200 holds an SNP report over cpu_rd (plus 16 zero bytes) and the
H200's SPDM transcript over gpu_report_data(cpu_rd)[:32], captured together inside the
SEV-SNP VM with the GPU in confidential mode: exactly what the node ships per session.
"""

import hashlib
import json
from pathlib import Path

import pytest

from attestrag.attest import AttestationError, CompositeClaims, CompositeEvidence, CompositeVerifier, Evidence, Platform, gpu_report_data
from attestrag.attest.nvidia import NvidiaVerifier
from attestrag.attest.snp import SnpVerifier
from attestrag.policy import Policy, evaluate
from tests.test_snp import H200Kds, POLICY_FILE

FIX = Path(__file__).parent / "fixtures" / "composite" / "h200"
OTHER_GPU = Path(__file__).parent / "fixtures" / "nvidia" / "h200"


@pytest.fixture(scope="module")
def pair():
    meta = json.loads((FIX / "meta.json").read_text())
    snp_ev = Evidence(Platform.SEV_SNP, (FIX / "snp-report.bin").read_bytes(), b"")
    gpu_ev = Evidence(Platform.NVIDIA_CC, (FIX / "gpu-report.bin").read_bytes(), b"", ((FIX / "ak-chain.pem").read_bytes(),))
    clock = lambda: meta["verify_at"]  # noqa: E731
    cv = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(H200Kds(), clock=clock), Platform.NVIDIA_CC: NvidiaVerifier(clock=clock)})
    return meta, snp_ev, gpu_ev, cv


def test_bound_pair_verifies_and_policy_allows(pair):
    meta, snp_ev, gpu_ev, cv = pair
    rd = bytes.fromhex(meta["report_data"])
    cc = cv.verify(CompositeEvidence(snp_ev, (gpu_ev,)), rd)
    assert cc.cpu.measurement == meta["snp_measurement"] and len(cc.gpus) == 1
    assert cc.gpus[0].report_data == bytes.fromhex(meta["gpu_report_data"]) == gpu_report_data(rd)
    pol = Policy.from_json(POLICY_FILE.read_text())
    assert pol.require_gpu and cc.gpus[0].measurement in pol.allowed_gpu_measurements
    d = evaluate(pol, cc, meta["verify_at"])
    assert d.allow, d.reasons
    # the same policy denies the CPU half on its own, and a GPU with other firmware measurements
    assert evaluate(pol, CompositeClaims(cc.cpu), meta["verify_at"]).reasons == ("gpu: GPU evidence required but none presented",)
    other = Policy(**{**pol.__dict__, "allowed_gpu_measurements": frozenset({"00" * 48})})
    assert "gpu[0]: measurement not in allow-list" in evaluate(other, cc, meta["verify_at"]).reasons


def test_forwarded_gpu_report_is_rejected(pair):
    """A real transcript from another session (the nvidia fixture) under this session's CPU report."""
    meta, snp_ev, _, cv = pair
    foreign = Evidence(Platform.NVIDIA_CC, (OTHER_GPU / "report.bin").read_bytes(), b"", ((OTHER_GPU / "ak-chain.pem").read_bytes(),))
    with pytest.raises(AttestationError, match="request nonce"):
        cv.verify(CompositeEvidence(snp_ev, (foreign,)), bytes.fromhex(meta["report_data"]))


def test_wrong_session_rejects_both_halves(pair):
    meta, snp_ev, gpu_ev, cv = pair
    with pytest.raises(AttestationError):
        cv.verify(CompositeEvidence(snp_ev, (gpu_ev,)), hashlib.sha384(b"another session").digest())
