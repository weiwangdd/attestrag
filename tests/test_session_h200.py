"""Session golden case: evidence exactly as the h200 node ships it through /attestation.

tests/fixtures/composite/h200-session: the composite evidence for one nonce, the node's transport
public key, verified the way the KBS and the client do it (CompositeVerifier.verify_for), i.e.
the CPU report_data is recomputed from nonce, pk and the GPU identity found in the evidence.
"""

import json
from pathlib import Path

import pytest

from attestrag.attest import AttestationError, CompositeEvidence, CompositeVerifier, Platform
from attestrag.attest.base import gpu_identity
from attestrag.attest.binding import cpu_report_data
from attestrag.attest.nvidia import NvidiaVerifier
from attestrag.attest.nvidia_rim import OcspClient, RimClient
from attestrag.attest.snp import SnpVerifier
from attestrag.policy import Policy, evaluate
from attestrag.transport import evidence_from_dict
from tests.test_snp import H200Kds, POLICY_FILE

FIX = Path(__file__).parent / "fixtures" / "composite" / "h200-session"
NV = Path(__file__).parent / "fixtures" / "nvidia" / "h200"
pytestmark = pytest.mark.skipif(not (FIX / "evidence.json").exists(), reason="session fixture not captured")


@pytest.fixture(scope="module")
def session():
    meta = json.loads((FIX / "meta.json").read_text())
    ev = evidence_from_dict(json.loads((FIX / "evidence.json").read_text()))
    clock = lambda: meta["verify_at"]  # noqa: E731
    nv = NvidiaVerifier(clock=clock, rim=RimClient(cache_dir=NV / "rim", offline=True), ocsp=OcspClient(cache_dir=NV / "ocsp", offline=True))
    cv = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(H200Kds(), clock=clock), Platform.NVIDIA_CC: nv})
    return meta, ev, cv


def test_session_verifies_with_gpu_identity_and_policy_allows(session):
    meta, ev, cv = session
    nonce, pk = bytes.fromhex(meta["nonce"]), bytes.fromhex(meta["node_pub"])
    cc = cv.verify_for(ev, nonce, pk)
    assert len(cc.gpus) == 1
    gid = gpu_identity(ev.gpus[0])
    assert cc.cpu.report_data == cpu_report_data(nonce, pk, [gid])      # the PSP signed the GPU identity
    assert cc.cpu.report_data != cpu_report_data(nonce, pk)             # and it is not the GPU-less binding
    pol = Policy.from_json(POLICY_FILE.read_text())
    d = evaluate(pol, cc, meta["verify_at"])
    assert d.allow, d.reasons


def test_session_rejects_other_nonce_pk_or_gpu(session):
    meta, ev, cv = session
    nonce, pk = bytes.fromhex(meta["nonce"]), bytes.fromhex(meta["node_pub"])
    with pytest.raises(AttestationError):
        cv.verify_for(ev, bytes(32), pk)
    with pytest.raises(AttestationError):
        cv.verify_for(ev, nonce, bytes(32))
    # the standalone GPU transcript of the same card (another session) in place of this session's GPU half:
    # same identity, wrong nonce -> rejected on the GPU binding
    other = evidence_from_dict({"cpu": json.loads((FIX / "evidence.json").read_text())["cpu"],
                                "gpus": [{"platform": "nvidia-cc", "report": (NV / "report.bin").read_bytes().hex(),
                                          "signature": "", "cert_chain": [(NV / "ak-chain.pem").read_bytes().hex()]}]})
    with pytest.raises(AttestationError, match="nonce"):
        cv.verify_for(other, nonce, pk)
    # without the GPU half the CPU report no longer matches: the identity is part of what the PSP signed
    with pytest.raises(AttestationError):
        cv.verify_for(CompositeEvidence(ev.cpu, ()), nonce, pk)
