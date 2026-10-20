import dataclasses

import pytest

from attestrag.attest import AttestationError, CompositeEvidence, cpu_report_data
from attestrag.attest.mock import MockAttester, MockVendor


def test_valid_evidence_verifies(make_attester, verifier):
    rd = cpu_report_data(b"n" * 32, b"k" * 32)
    claims = verifier.verify(make_attester(gpus=1).attest(rd), rd)
    assert claims.cpu.report_data == rd and len(claims.gpus) == 1


def test_wrong_nonce_rejected(make_attester, verifier):
    ev = make_attester().attest(cpu_report_data(b"a" * 32, b"k" * 32))
    with pytest.raises(AttestationError, match="report_data"):
        verifier.verify(ev, cpu_report_data(b"b" * 32, b"k" * 32))


def test_tampered_report_rejected(make_attester, verifier):
    rd = cpu_report_data(b"n" * 32, b"k" * 32)
    ev = make_attester().attest(rd)
    bad = dataclasses.replace(ev.cpu, report=ev.cpu.report.replace(b'"debug":false', b'"debug":true '))
    with pytest.raises(AttestationError, match="signature"):
        verifier.verify(CompositeEvidence(bad), rd)


def test_untrusted_vendor_rejected(verifier):
    rogue = MockVendor("mock-amd")  # same name, different key
    from attestrag.attest import CompositeAttester
    rd = cpu_report_data(b"n" * 32, b"k" * 32)
    with pytest.raises(AttestationError):
        verifier.verify(CompositeAttester(MockAttester(rogue)).attest(rd), rd)


def test_gpu_evidence_from_other_session_rejected(make_attester, verifier):
    att = make_attester(gpus=1)
    rd1 = cpu_report_data(b"1" * 32, b"k" * 32)
    rd2 = cpu_report_data(b"2" * 32, b"k" * 32)
    ev1, ev2 = att.attest(rd1), att.attest(rd2)
    spliced = CompositeEvidence(ev2.cpu, ev1.gpus)  # replay GPU report from session 1
    with pytest.raises(AttestationError, match="report_data"):
        verifier.verify(spliced, rd2)
