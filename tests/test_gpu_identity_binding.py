"""The CPU report commits to the attached GPU's identity: a GPU half substituted in transit is rejected.

This is the attack the Tamarin model found against the previous binding (formal/README.md): the
operator owns another certified confidential GPU, has it sign this session's GPU nonce (public),
and swaps the GPU evidence. With the identity inside report_data the swapped evidence changes the
expected report_data and the CPU report no longer verifies.
"""

import os

import pytest

from attestrag.attest import AttestationError, CompositeAttester, CompositeEvidence, CompositeVerifier, Platform
from attestrag.attest.base import gpu_identity
from attestrag.attest.binding import cpu_report_data, gpu_report_data
from attestrag.attest.mock import MockAttester, MockTEEConfig, MockVendor, MockVerifier


def _setup():
    amd, nv = MockVendor("amd"), MockVendor("nvidia")
    gpu_a = MockAttester(MockVendor("gpu-a"), MockTEEConfig(Platform.MOCK_GPU, "aa" * 48))
    gpu_b = MockAttester(MockVendor("gpu-b"), MockTEEConfig(Platform.MOCK_GPU, "aa" * 48))   # same firmware, other device
    tee = CompositeAttester(MockAttester(amd, MockTEEConfig(measurement="cc" * 48)), [gpu_a])
    roots = {amd.name: amd.root_public, gpu_a.vendor.name: gpu_a.vendor.root_public, gpu_b.vendor.name: gpu_b.vendor.root_public}
    cv = CompositeVerifier({Platform.MOCK_CPU: MockVerifier(roots), Platform.MOCK_GPU: MockVerifier(roots)})
    return tee, gpu_a, gpu_b, cv


def test_session_evidence_commits_to_gpu_identity():
    tee, gpu_a, _, cv = _setup()
    nonce, pk = os.urandom(32), os.urandom(32)
    ev = tee.attest_for(nonce, pk)
    cc = cv.verify_for(ev, nonce, pk)
    assert len(cc.gpus) == 1
    assert cc.cpu.report_data == cpu_report_data(nonce, pk, [gpu_a.identity()])
    assert gpu_identity(ev.gpus[0]) == gpu_a.identity()
    assert cc.cpu.report_data != cpu_report_data(nonce, pk)            # not the GPU-less binding
    with pytest.raises(AttestationError):
        cv.verify_for(ev, os.urandom(32), pk)                             # other session


def test_substituted_gpu_half_is_rejected():
    tee, gpu_a, gpu_b, cv = _setup()
    nonce, pk = os.urandom(32), os.urandom(32)
    ev = tee.attest_for(nonce, pk)
    # the operator reconstructs this session's GPU nonce from public values and has GPU B sign it
    rd = cpu_report_data(nonce, pk, [gpu_identity(ev.gpus[0])])
    forged = gpu_b.attest(gpu_report_data(rd))
    swapped = CompositeEvidence(ev.cpu, (forged,))
    # the previous binding (report_data without identities, verified against the attacker-known rd) accepted it
    assert cv.verify(swapped, rd).gpus[0].signer == "gpu-b"
    # the session binding does not: the identity in the evidence no longer matches the CPU report
    with pytest.raises(AttestationError):
        cv.verify_for(swapped, nonce, pk)


def test_cpu_only_sessions_unchanged():
    amd = MockVendor("amd")
    tee = CompositeAttester(MockAttester(amd, MockTEEConfig(measurement="cc" * 48)))
    cv = CompositeVerifier({Platform.MOCK_CPU: MockVerifier({amd.name: amd.root_public})})
    nonce, pk = os.urandom(32), os.urandom(32)
    cc = cv.verify_for(tee.attest_for(nonce, pk), nonce, pk)
    assert cc.cpu.report_data == cpu_report_data(nonce, pk) and cc.gpus == ()
