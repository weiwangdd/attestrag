"""NVIDIA GPU attestation verifier against a synthetic SPDM transcript.

No GPU here: a test CA stands in for NVIDIA's Device Identity CA, an AK certificate
carries a DICE FWID extension, and the transcript is laid out exactly as the GPU
returns it (37-byte request || MEASUREMENTS response with a raw P-384 signature).
A real H200 transcript (tests/fixtures/nvidia/h200) is the golden case: captured
inside the SEV-SNP guest with the GPU in CC mode.
"""

import datetime as dt
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from attestrag.attest import AttestationError, CompositeVerifier, Evidence, Platform, gpu_report_data
from attestrag.attest.nvidia import NONCE_LEN, GpuReport, NvidiaVerifier
from attestrag.policy import Policy, evaluate

NOW = dt.datetime(2026, 10, 23, tzinfo=dt.timezone.utc)
FWID = bytes(range(48))


def _cert(subject, issuer_name, key, issuer_key, ca, fwid=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if fwid is not None:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("2.23.133.5.4.1"), b"\x30\x04" + fwid), critical=False)
    return b.sign(issuer_key, hashes.SHA384())


@pytest.fixture(scope="module")
def pki():
    root_key, ak_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Device Identity CA")])
    ak_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test GPU AK")])
    root = _cert(root_name, root_name, root_key, root_key, ca=True)
    ak = _cert(ak_name, root_name, ak_key, root_key, ca=False, fwid=FWID)
    chain_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (ak, root))
    return root, ak, ak_key, chain_pem


def dmtf(value: bytes) -> bytes:
    return bytes([1]) + len(value).to_bytes(2, "little") + value


def transcript(ak_key, nonce: bytes, blocks, opaque: dict[int, bytes], tamper=None) -> bytes:
    req = bytes([0x11, 0xE0, 0x01, 0xFF]) + nonce + bytes([0])
    record = b"".join(bytes([idx, 1]) + len(dmtf(v)).to_bytes(2, "little") + dmtf(v) for idx, v in blocks)
    opq = b"".join(struct.pack("<HH", t, len(v)) + v for t, v in opaque.items())
    responder_nonce = hashlib.sha256(b"gpu-chosen" + nonce).digest()  # the GPU picks its own, as SPDM says
    body = bytes([0x11, 0x60, 0, 0, len(blocks)]) + len(record).to_bytes(3, "little") + record + responder_nonce + len(opq).to_bytes(2, "little") + opq
    der = ak_key.sign(req + body, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    blob = req + body + sig
    if tamper is not None:
        b = bytearray(blob)
        b[tamper] ^= 1
        blob = bytes(b)
    return blob


BLOCKS = [(1, hashlib.sha384(b"vbios").digest()), (2, hashlib.sha384(b"driver").digest()), (36, b"\x00" * 48)]
OPAQUE = {3: b"580.196.07\0", 6: b"96.00.b7.00.02\0", 20: FWID, 12: b"\x03"}


def test_parse_layout(pki):
    _, _, ak_key, _ = pki
    nonce = bytes(range(NONCE_LEN))
    rep = GpuReport.parse(transcript(ak_key, nonce, BLOCKS, OPAQUE))
    assert rep.nonce == nonce and rep.responder_nonce != nonce and len(rep.measurements) == 3 and rep.measurements[0] == (1, BLOCKS[0][1])
    assert rep.opaque_str("driver_version") == "580.196.07" and rep.opaque["fwid"] == FWID
    assert len(rep.signature) == 96 and rep.signed_data == transcript(ak_key, nonce, BLOCKS, OPAQUE)[:-96]


def test_verify_and_bind(pki):
    root, ak, ak_key, chain_pem = pki
    cpu_rd = hashlib.sha384(b"cpu report data").digest()
    rd = gpu_report_data(cpu_rd)
    blob = transcript(ak_key, rd[:NONCE_LEN], BLOCKS, OPAQUE)
    v = NvidiaVerifier(roots=[root], clock=lambda: NOW.timestamp())
    c = v.verify(Evidence(Platform.NVIDIA_CC, blob, b"", (chain_pem,)), rd)
    assert c.platform == Platform.NVIDIA_CC and c.signer == "nvidia-device-identity-ca"
    assert c.measurement == GpuReport.parse(blob).composite_measurement.hex()
    assert c.extra["driver_version"] == "580.196.07" and c.extra["fwid"] == FWID.hex() and c.extra["msr_1"] == BLOCKS[0][1].hex()
    # policy pins the composite digest
    pol = Policy(allowed_cpu_platforms=frozenset({Platform.MOCK_CPU}), allowed_measurements=frozenset(),
                 require_gpu=True, allowed_gpu_platforms=frozenset({Platform.NVIDIA_CC}),
                 allowed_gpu_measurements=frozenset({c.measurement}))
    from attestrag.attest import CompositeClaims
    from attestrag.attest.types import Claims
    cpu = Claims(Platform.MOCK_CPU, "aa", {}, cpu_rd, False, NOW.timestamp())
    d = evaluate(Policy(**{**pol.__dict__, "allowed_measurements": frozenset({"aa"})}), CompositeClaims(cpu, (c,)), NOW.timestamp())
    assert d.allow, d.reasons
    other = Policy(**{**pol.__dict__, "allowed_measurements": frozenset({"aa"}), "allowed_gpu_measurements": frozenset({"00" * 48})})
    assert "gpu[0]: measurement not in allow-list" in evaluate(other, CompositeClaims(cpu, (c,)), NOW.timestamp()).reasons


@pytest.mark.parametrize("what", ["signature", "nonce", "root", "fwid", "replayed-session"])
def test_rejections(pki, what):
    root, ak, ak_key, chain_pem = pki
    rd = gpu_report_data(hashlib.sha384(b"cpu").digest())
    v = NvidiaVerifier(roots=[root], clock=lambda: NOW.timestamp())
    blob, chain, expect = transcript(ak_key, rd[:NONCE_LEN], BLOCKS, OPAQUE), chain_pem, rd
    if what == "signature":
        blob = transcript(ak_key, rd[:NONCE_LEN], BLOCKS, OPAQUE, tamper=50)  # inside the measurement record
    elif what == "nonce":
        expect = gpu_report_data(hashlib.sha384(b"another session").digest())
    elif what == "root":
        other_root = _cert(root.subject, root.subject, ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1()), ca=True)
        v = NvidiaVerifier(roots=[other_root], clock=lambda: NOW.timestamp())
    elif what == "fwid":
        blob = transcript(ak_key, rd[:NONCE_LEN], BLOCKS, {**OPAQUE, 20: bytes(48)})
    elif what == "replayed-session":
        blob = transcript(ak_key, bytes(32), BLOCKS, OPAQUE)
    with pytest.raises(AttestationError):
        v.verify(Evidence(Platform.NVIDIA_CC, blob, b"", (chain,)), expect)


def test_composite_verifier_routes_gpu_evidence(pki):
    root, ak, ak_key, chain_pem = pki
    from attestrag.attest.mock import MockAttester, MockTEEConfig, MockVendor, MockVerifier
    vendor = MockVendor()
    cpu_att = MockAttester(vendor, MockTEEConfig(measurement="aa" * 48))
    cpu_rd = hashlib.sha384(b"session").digest()
    cpu_ev = cpu_att.attest(cpu_rd)
    gpu_ev = Evidence(Platform.NVIDIA_CC, transcript(ak_key, gpu_report_data(cpu_rd)[:NONCE_LEN], BLOCKS, OPAQUE), b"", (chain_pem,))
    from attestrag.attest import CompositeEvidence
    cv = CompositeVerifier({Platform.MOCK_CPU: MockVerifier({vendor.name: vendor.root_public}), Platform.NVIDIA_CC: NvidiaVerifier(roots=[root], clock=lambda: NOW.timestamp())})
    cc = cv.verify(CompositeEvidence(cpu_ev, (gpu_ev,)), cpu_rd)
    assert len(cc.gpus) == 1 and cc.gpus[0].extra["vbios_version"] == "96.00.b7.00.02"


def test_pinned_nvidia_root_is_loaded():
    v = NvidiaVerifier()
    subjects = [r.subject.rfc4514_string() for r in v.roots.values()]
    assert any("NVIDIA Device Identity CA" in s for s in subjects)


FIX = Path(__file__).parent / "fixtures" / "nvidia" / "h200"


def test_real_h200_transcript_verifies_against_pinned_root():
    meta = json.loads((FIX / "meta.json").read_text())
    blob, chain, nonce = (FIX / "report.bin").read_bytes(), (FIX / "ak-chain.pem").read_bytes(), (FIX / "nonce.bin").read_bytes()
    rep = GpuReport.parse(blob)
    assert rep.nonce == nonce and rep.responder_nonce != nonce and len(rep.measurements) == 64
    v = NvidiaVerifier(clock=lambda: meta["verify_at"])
    c = v.verify(Evidence(Platform.NVIDIA_CC, blob, b"", (chain,)), nonce + bytes(16))
    assert c.signer == "nvidia-device-identity-ca" and c.extra["driver_version"] == "580.178.04"
    assert c.extra["vbios_version"] == "96.00.b7.00.02"  # 5 binary bytes on the wire, nvidia-smi notation here
    assert c.extra["ak_subject"].startswith("CN=GH100 A01 GSP FMC LF") and len(c.extra["fwid"]) == 96
    assert c.measurement == rep.composite_measurement.hex()
    # the request nonce is what binds: any other session value is rejected
    with pytest.raises(AttestationError):
        v.verify(Evidence(Platform.NVIDIA_CC, blob, b"", (chain,)), hashlib.sha384(b"other").digest())
