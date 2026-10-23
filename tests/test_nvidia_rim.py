"""NVIDIA reference manifests (RIM) and OCSP: the real driver manifest for the H200, a synthetic OCSP PKI."""

import datetime as dt
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from attestrag.attest import AttestationError, Evidence, Platform
from attestrag.attest.nvidia import GpuReport, NvidiaVerifier, load_roots
from attestrag.attest.nvidia_rim import (OcspClient, ReferenceManifest, RimClient, driver_rim_id, match_measurements,
                                         merge_golden, vbios_rim_id)
from attestrag.policy import Policy, evaluate
from tests.test_nvidia import _cert

H200 = Path(__file__).parent / "fixtures" / "nvidia" / "h200"
SAMPLES = Path(__file__).parent / "fixtures" / "nvidia" / "rim-samples"
NOW = dt.datetime(2026, 10, 23, tzinfo=dt.timezone.utc)
signxml = pytest.importorskip("signxml", reason="RIM signature checks need signxml")


def test_rim_ids_follow_nvidia_naming():
    assert driver_rim_id("580.178.04") == "NV_GPU_DRIVER_GH100_580.178.04"
    assert vbios_rim_id("1010\0", "0230", "894\0\0", "96.00.b7.00.02") == "NV_GPU_VBIOS_1010_0230_894_9600B70002"


@pytest.fixture(scope="module")
def driver_rim():
    return ReferenceManifest.parse((H200 / "rim" / "NV_GPU_DRIVER_GH100_580.178.04.swidtag").read_bytes())


def test_driver_manifest_parses_and_verifies(driver_rim):
    assert driver_rim.version == "580.178.04" and driver_rim.product == "GH100" and len(driver_rim.entries) == 64
    assert set(driver_rim.active()) == {7, *range(21, 42)}
    assert driver_rim.cert_chain[0].subject.rfc4514_string().startswith("CN=HCC RIM L4 Signer")
    leaf = driver_rim.verify(load_roots("corim_*.pem"), NOW.timestamp())
    assert leaf is driver_rim.cert_chain[0]
    with pytest.raises(AttestationError, match="pinned"):
        driver_rim.verify({}, NOW.timestamp())


def test_tampered_manifest_fails_signature(driver_rim):
    xml = driver_rim.xml
    i = xml.index(b'Hash0="') + 7
    bad = xml[:i] + (b"0" if xml[i:i + 1] != b"0" else b"1") + xml[i + 1:]
    with pytest.raises(AttestationError, match="signature"):
        ReferenceManifest.parse(bad).verify(load_roots("corim_*.pem"), NOW.timestamp())


def test_h200_report_matches_driver_manifest(driver_rim):
    rep = GpuReport.parse((H200 / "report.bin").read_bytes())
    blocks = [v for _, v in rep.measurements]
    matched = match_measurements(blocks, merge_golden(driver_rim, None))
    assert matched == [7, *range(21, 42)]
    # one block changed -> named mismatch; an H100 VBIOS manifest -> this card's VBIOS blocks differ
    blocks[22] = bytes(48)
    with pytest.raises(AttestationError, match="index 22 \\(driver\\)"):
        match_measurements(blocks, merge_golden(driver_rim, None))
    h100 = ReferenceManifest.parse((SAMPLES / "NV_GPU_VBIOS_1010_0200_882_96005E0001.swidtag").read_bytes())
    assert h100.version == "96.00.5e.00.01" and set(h100.active()) == {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12}
    with pytest.raises(AttestationError, match="vbios"):
        match_measurements([v for _, v in rep.measurements], merge_golden(driver_rim, h100))
    # both manifests claiming one index is a manifest error, not a measurement error
    with pytest.raises(AttestationError, match="both claim"):
        merge_golden(driver_rim, driver_rim)


def test_rim_client_offline_cache(tmp_path):
    c = RimClient(cache_dir=H200 / "rim", offline=True)
    assert c.fetch("NV_GPU_DRIVER_GH100_580.178.04") is not None
    assert c.fetch("NV_GPU_VBIOS_1010_0230_894_9600B70002") is None     # NVIDIA has not published it (.missing marker)
    with pytest.raises(AttestationError, match="offline"):
        RimClient(cache_dir=tmp_path, offline=True).fetch("NV_GPU_DRIVER_GH100_0.0")
    with pytest.raises(AttestationError, match="bad RIM id"):
        c.fetch("../etc/passwd")


def test_verifier_records_manifest_results_and_policy_can_require_them():
    meta = json.loads((H200 / "meta.json").read_text())
    v = NvidiaVerifier(clock=lambda: meta["verify_at"], rim=RimClient(cache_dir=H200 / "rim", offline=True))
    ev = Evidence(Platform.NVIDIA_CC, (H200 / "report.bin").read_bytes(), b"", ((H200 / "ak-chain.pem").read_bytes(),))
    c = v.verify(ev, (H200 / "nonce.bin").read_bytes() + bytes(16))
    assert c.extra["rim_driver"] == "ok:NV_GPU_DRIVER_GH100_580.178.04"
    assert c.extra["rim_vbios"] == "not-found:NV_GPU_VBIOS_1010_0230_894_9600B70002"
    # NVDEC0 is disabled on this card (opaque nvdec0_status 0x55), so manifest index 35 is not measured and not compared
    assert c.extra["rim_matched"] == ",".join(str(i) for i in [7, *range(21, 35), *range(36, 42)]) and "ocsp" not in c.extra
    from attestrag.attest import CompositeClaims
    from attestrag.attest.types import Claims
    cpu = Claims(Platform.MOCK_CPU, "aa", {}, bytes(48), False, meta["verify_at"])
    base = dict(allowed_cpu_platforms=frozenset({Platform.MOCK_CPU}), allowed_measurements=frozenset({"aa"}),
                require_gpu=True, allowed_gpu_platforms=frozenset({Platform.NVIDIA_CC}))
    assert evaluate(Policy(**base), CompositeClaims(cpu, (c,)), meta["verify_at"]).allow
    d = evaluate(Policy(**base, require_gpu_rim=True, require_gpu_ocsp=True), CompositeClaims(cpu, (c,)), meta["verify_at"])
    assert any("reference manifests not verified" in r and "not-found" in r for r in d.reasons)
    assert "gpu[0]: certificate revocation not checked" in d.reasons
    assert Policy.from_dict({**{k: list(v) if isinstance(v, frozenset) else v for k, v in base.items()},
                             "allowed_cpu_platforms": ["mock-cpu"], "allowed_gpu_platforms": ["nvidia-cc"],
                             "require_gpu_rim": True}).require_gpu_rim


# --- OCSP against a synthetic PKI ---------------------------------------------------------------

@pytest.fixture(scope="module")
def ocsp_pki():
    ca_key, sub_key, resp_key, other_key = (ec.generate_private_key(ec.SECP384R1()) for _ in range(4))
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = _cert(ca_name, ca_name, ca_key, ca_key, ca=True)
    sub = _cert(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Sub")]), ca_name, sub_key, ca_key, ca=True)
    resp_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test OCSP Responder")])
    responder = (x509.CertificateBuilder().subject_name(resp_name).issuer_name(ca_name).public_key(resp_key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=30))
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False).sign(ca_key, hashes.SHA384()))
    return ca, ca_key, sub, responder, resp_key, other_key


def _response(pki, status=ocsp.OCSPCertStatus.GOOD, nonce=None, signer=None, serial=None, this=None):
    ca, ca_key, sub, responder, resp_key, other_key = pki
    this = this or NOW
    b = ocsp.OCSPResponseBuilder().add_response(
        cert=sub, issuer=ca, algorithm=hashes.SHA384(), cert_status=status, this_update=this.replace(tzinfo=None),
        next_update=(this + dt.timedelta(days=1)).replace(tzinfo=None),
        revocation_time=this.replace(tzinfo=None) if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=x509.ReasonFlags.key_compromise if status == ocsp.OCSPCertStatus.REVOKED else None)
    key = resp_key
    if signer is not None:   # a responder nobody certified: self-signed with its own key
        key = signer
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Responder")])
        responder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                     .serial_number(1).not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=30))
                     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False).sign(key, hashes.SHA384()))
    b = b.responder_id(ocsp.OCSPResponderEncoding.NAME, responder).certificates([responder])
    if nonce is not None:
        b = b.add_extension(x509.OCSPNonce(nonce), critical=False)
    return b.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.DER)


class _Fake(OcspClient):
    """OcspClient whose transport returns a canned response (and echoes the request nonce when asked)."""

    def __init__(self, pki, cache_dir, **kw):
        super().__init__(cache_dir=cache_dir, **kw)
        self.pki, self.kw, self.calls = pki, {}, 0

    def _post(self, der):
        self.calls += 1
        req = ocsp.load_der_ocsp_request(der)
        nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        kw = dict(self.kw)
        if kw.pop("echo_nonce", True):
            kw["nonce"] = nonce
        return _response(self.pki, **kw)


def test_ocsp_good_is_cached_and_bad_answers_are_rejected(ocsp_pki, tmp_path):
    ca, ca_key, sub, responder, resp_key, other_key = ocsp_pki
    now = NOW.timestamp()
    c = _Fake(ocsp_pki, tmp_path / "a")
    assert c.check(sub, ca, now).certificate_status == ocsp.OCSPCertStatus.GOOD
    c.check(sub, ca, now)
    assert c.calls == 1                                     # second check served from the cache
    assert c.check_chain([sub, ca], now) == [sub.subject.rfc4514_string()]
    with pytest.raises(AttestationError, match="validity"):
        c.check(sub, ca, now + 5 * 86400)                   # cached response expired, refetch is also "old"
    cases = {
        "revoked": (dict(status=ocsp.OCSPCertStatus.REVOKED), "revoked \\(key_compromise\\)"),
        "unknown": (dict(status=ocsp.OCSPCertStatus.UNKNOWN), "unknown"),
        "nonce": (dict(echo_nonce=False, nonce=os.urandom(16)), "nonce mismatch"),
        "no-nonce": (dict(echo_nonce=False), "no nonce"),
        "signer": (dict(signer=other_key), "not signed by"),
    }
    for name, (kw, msg) in cases.items():
        f = _Fake(ocsp_pki, tmp_path / name)
        f.kw = kw
        with pytest.raises(AttestationError, match=msg):
            f.check(sub, ca, now)
    with pytest.raises(AttestationError, match="offline"):
        _Fake(ocsp_pki, tmp_path / "off", offline=True).check(sub, ca, now)
