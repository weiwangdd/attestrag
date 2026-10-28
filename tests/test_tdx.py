"""Intel TDX verifier against synthetic DCAP v4 quotes (tests/tdx_fixture.py) and, when captured, the real
quote from a GCP C3 TD (tests/fixtures/tdx/gcp-c3)."""

import json
from pathlib import Path

import pytest

from attestrag.attest import AttestationError, Evidence, Platform
from attestrag.attest import tdx
from attestrag.attest.binding import cpu_report_data
from attestrag.policy import Policy, evaluate
from tests.tdx_fixture import FIXED_NOW, FakeIntel, FakePcs

RD = cpu_report_data(b"n" * 32, b"k" * 32)


@pytest.fixture(scope="module")
def intel():
    return FakeIntel()


def verifier(intel, pcs=None, now=FIXED_NOW):
    return tdx.TdxVerifier(pcs or FakePcs(intel), root_pin=intel.pin, clock=lambda: now)


def ev(quote: bytes) -> Evidence:
    return Evidence(Platform.TDX, quote, b"", ())


def test_quote_layout_parses(intel):
    q = tdx.TdxQuote.parse(intel.make_quote(RD))
    assert (q.version, q.att_key_type, q.tee_type) == (4, 2, 0x81)
    assert q.td.mr_td == b"\x7d" * 48 and q.td.report_data == RD.ljust(64, b"\0") and q.td.rtmr[2] == b"\x12" * 48
    assert q.qe_report.isv_prod_id == 2 and q.qe_report.isv_svn == 8 and len(q.pck_chain_pem) > 1000
    assert tdx.PckInfo.from_cert(tdx.x509.load_pem_x509_certificates(q.pck_chain_pem)[0]) == \
        tdx.PckInfo(intel.fmspc.hex(), "0000", intel.cpu_svn, 13, 0)


def test_synthetic_quote_verifies_and_policy_allows(intel):
    pcs = FakePcs(intel)
    c = verifier(intel, pcs).verify(ev(intel.make_quote(RD)), RD)
    assert c.platform is Platform.TDX and c.measurement == "7d" * 48 and c.report_data == RD and not c.debug
    assert c.tcb == {"status": 4, "pcesvn": 13, "tdx_module_svn": 5, "tdx_module_major": 3, "qe_svn": 8, "tcb_evaluation": 17}
    assert c.extra["tcb_status"] == "UpToDate" and c.extra["rtmr0"] == "10" * 48 and c.extra["fmspc"] == intel.fmspc.hex()
    assert c.extra["tdx_module"] == "TDX_03" and c.extra["pck_ca"] == "Intel SGX PCK Platform CA" and c.signer == "intel-sgx-root-ca"
    assert pcs.calls == [("tcb", intel.fmspc.hex()), ("qe", None)]
    pol = Policy(allowed_cpu_platforms=frozenset({Platform.TDX}), allowed_measurements=frozenset({"7d" * 48}),
                 min_tcb={"status": 4, "pcesvn": 13, "tcb_evaluation": 17})
    from attestrag.attest.types import CompositeClaims
    assert evaluate(pol, CompositeClaims(c), FIXED_NOW).allow
    assert "cpu: platform tdx not allowed" in evaluate(Policy.from_dict({"allowed_cpu_platforms": ["sev-snp"], "allowed_measurements": ["7d" * 48]}),
                                                      CompositeClaims(c), FIXED_NOW).reasons


def test_rejects_wrong_report_data(intel):
    with pytest.raises(AttestationError, match="report_data"):
        verifier(intel).verify(ev(intel.make_quote(RD)), cpu_report_data(b"x" * 32, b"k" * 32))


def test_rejects_tampered_quote_and_qe_report(intel):
    raw = bytearray(intel.make_quote(RD))
    bad = bytearray(raw); bad[tdx.HEADER_LEN + 16 + 48 * 3 + 8 * 3] ^= 1    # one bit of MRTD
    with pytest.raises(AttestationError, match="quote: bad signature"):
        verifier(intel).verify(ev(bytes(bad)), RD)
    bad = bytearray(raw); bad[tdx.SIGNED_LEN + 4 + 134 + 64] ^= 1          # one bit of the QE report (mr_enclave)
    with pytest.raises(AttestationError, match="QE report: bad signature"):
        verifier(intel).verify(ev(bytes(bad)), RD)
    with pytest.raises(AttestationError, match="unsupported quote version"):
        verifier(intel).verify(ev(intel.make_quote(RD, version=3)), RD)
    with pytest.raises(AttestationError, match="not for TDX"):
        verifier(intel).verify(ev(intel.make_quote(RD, tee_type=0)), RD)


def test_attestation_key_must_be_certified_by_the_qe(intel):
    """A quote signed by some other P-256 key, with the QE report left certifying the real one."""
    from cryptography.hazmat.primitives.asymmetric import ec
    rogue = ec.generate_private_key(ec.SECP256R1())
    q = intel.make_quote(RD, ak_key=rogue, certify_ak=intel.ak_raw())
    with pytest.raises(AttestationError, match="does not certify this attestation key"):
        verifier(intel).verify(ev(q), RD)


def test_chain_must_end_in_the_pinned_root(intel):
    other = FakeIntel()
    v = tdx.TdxVerifier(FakePcs(intel), root_pin=other.pin, clock=lambda: FIXED_NOW)
    with pytest.raises(AttestationError, match="pinned Intel SGX Root CA"):
        v.verify(ev(intel.make_quote(RD)), RD)
    q = intel.make_quote(RD, chain_pem=other.chain_pem())   # someone else's chain glued onto this quote
    with pytest.raises(AttestationError):
        verifier(intel).verify(ev(q), RD)
    with pytest.raises(AttestationError, match="not valid now"):
        verifier(intel, now=FIXED_NOW + 40 * 365 * 86400).verify(ev(intel.make_quote(RD)), RD)


def test_tcb_out_of_date_is_surfaced_not_hidden():
    old = FakeIntel(cpu_svn=bytes([1] * 16), pce_svn=11)   # matches only the second level
    c = verifier(old).verify(ev(old.make_quote(RD)), RD)
    assert c.tcb["status"] == 0 and c.extra["tcb_status"] == "OutOfDate" and c.extra["advisory_ids"] == "INTEL-SA-00001"
    from attestrag.attest.types import CompositeClaims
    pol = Policy(allowed_cpu_platforms=frozenset({Platform.TDX}), allowed_measurements=frozenset({"7d" * 48}), min_tcb={"status": 4})
    d = evaluate(pol, CompositeClaims(c), FIXED_NOW)
    assert not d.allow and "cpu: tcb 'status'=0 < required 4" in d.reasons
    below = FakeIntel(cpu_svn=bytes([0] * 16), pce_svn=1)
    with pytest.raises(AttestationError, match="below every level"):
        verifier(below).verify(ev(below.make_quote(RD)), RD)


def test_tdx_module_and_qe_svn_levels(intel):
    c = verifier(intel).verify(ev(intel.make_quote(RD, tee_tcb_svn=bytes([3, 3] + [0] * 14))), RD)
    assert c.extra["tcb_status_module"] == "OutOfDate" and c.extra["tcb_status_platform"] == "UpToDate" and c.tcb["status"] == 0
    c = verifier(intel).verify(ev(intel.make_quote(RD, qe_isv_svn=6)), RD)
    assert c.extra["tcb_status_qe"] == "OutOfDate" and c.tcb["status"] == 0 and c.tcb["qe_svn"] == 6
    with pytest.raises(AttestationError, match="no TDX module identity for major version 4"):
        verifier(intel).verify(ev(intel.make_quote(RD, tee_tcb_svn=bytes([5, 4] + [0] * 14))), RD)


def test_pcs_responses_are_signed_and_dated(intel):
    body, chain = intel.tcb_info_response()
    tampered = body.replace(b'"tcbStatus":"OutOfDate"', b'"tcbStatus":"UpToDate"', 1)
    with pytest.raises(AttestationError, match="PCS tcbInfo: bad signature"):
        verifier(intel, FakePcs(intel, tcb=(tampered, chain))).verify(ev(intel.make_quote(RD)), RD)
    stale = intel.tcb_info_response(now=FIXED_NOW - 90 * 86400)
    with pytest.raises(AttestationError, match="tcbInfo not valid now"):
        verifier(intel, FakePcs(intel, tcb=stale)).verify(ev(intel.make_quote(RD)), RD)
    other = FakeIntel()
    with pytest.raises(AttestationError, match="pinned Intel SGX Root CA"):   # signed by someone else's TCB signing key
        verifier(intel, FakePcs(intel, qe=other.qe_identity_response())).verify(ev(intel.make_quote(RD)), RD)
    with pytest.raises(AttestationError, match="QE MRSIGNER"):
        verifier(intel, FakePcs(intel, qe=intel.qe_identity_response(mr_signer=b"\x00" * 32))).verify(ev(intel.make_quote(RD)), RD)


def test_debug_td_is_reported(intel):
    c = verifier(intel).verify(ev(intel.make_quote(RD, td_attributes=b"\x01" + bytes(7))), RD)
    assert c.debug and c.extra["td_attributes"] == "0100000000000000"


def test_pcs_cache_serves_offline(tmp_path, intel):
    import base64
    body, chain = intel.tcb_info_response()
    pcs = tdx.PcsClient(tmp_path, offline=True)
    with pytest.raises(AttestationError, match="offline"):
        pcs.tcb_info(intel.fmspc.hex())
    import hashlib
    url = f"{tdx.PCS_BASE}/tcb?fmspc={intel.fmspc.hex()}"
    (tmp_path / (hashlib.sha256(url.encode()).hexdigest() + ".json")).write_text(
        json.dumps({"url": url, "body": base64.b64encode(body).decode(), "chain": chain.decode()}))
    assert pcs.tcb_info(intel.fmspc.hex()) == (body, chain)


def test_raw_json_field_extraction():
    body = b'{"tcbInfo":{"a":{"b":"}"},"c":[1,{"d":"\\"}"}]},"signature":"00"}'
    assert tdx._raw_json_field(body, "tcbInfo") == b'{"a":{"b":"}"},"c":[1,{"d":"\\"}"}]}'
    with pytest.raises(AttestationError):
        tdx._raw_json_field(b'{"x":1}', "tcbInfo")


# ---------------------------------------------------------------- the real thing, once captured
FIX = Path(__file__).parent / "fixtures" / "tdx" / "gcp-c3"


@pytest.mark.skipif(not (FIX / "quote.bin").exists(), reason="GCP TDX fixture not captured")
def test_real_gcp_c3_quote():
    meta = json.loads((FIX / "meta.json").read_text())
    pcs = tdx.PcsClient(FIX / "pcs", offline=True)
    v = tdx.TdxVerifier(pcs, clock=lambda: meta["verify_at"])
    c = v.verify(Evidence(Platform.TDX, (FIX / "quote.bin").read_bytes(), b"", ()), bytes.fromhex(meta["report_data"]))
    assert c.measurement == meta["mr_td"] and c.extra["tcb_status"] == meta["tcb_status"] and not c.debug
    assert c.extra["fmspc"] == meta["fmspc"] and c.tcb["status"] == tdx.tcb_rank(meta["tcb_status"])
    with pytest.raises(AttestationError, match="report_data"):
        v.verify(Evidence(Platform.TDX, (FIX / "quote.bin").read_bytes(), b"", ()), bytes(48))
