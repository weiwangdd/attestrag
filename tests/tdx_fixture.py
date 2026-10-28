"""Synthetic Intel TDX evidence: a DCAP v4 quote with a fake Intel SGX Root CA -> PCK Platform CA -> PCK
chain, a fake TCB signing certificate, and TCB info / QE identity JSON signed with it, in the byte layout
and JSON shape of the real artifacts. Every key is generated here, so the verifier is configured with the
fake root pin (`FakeIntel.pin`)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from attestrag.attest import tdx

NOT_BEFORE = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2045, 1, 1, tzinfo=dt.timezone.utc)
FIXED_NOW = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc).timestamp()
QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")   # Intel's QE vendor id


# ---------------------------------------------------------------- DER helpers (the PCK SGX extension)

def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + body


def der_oid(s: str) -> bytes:
    parts = [int(p) for p in s.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return _der(0x06, out)


def der_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big", signed=True)
    return _der(0x02, b)


def der_octets(b: bytes) -> bytes:
    return _der(0x04, b)


def der_seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def sgx_extension(fmspc: bytes, pce_id: bytes, cpu_svn: bytes, pce_svn: int, sgx_type: int = 0) -> bytes:
    tcb = der_seq(*[der_seq(der_oid(f"{tdx.OID_TCB}.{i + 1}"), der_int(cpu_svn[i])) for i in range(16)],
                  der_seq(der_oid(tdx.OID_PCESVN), der_int(pce_svn)),
                  der_seq(der_oid(tdx.OID_CPUSVN), der_octets(cpu_svn)))
    return der_seq(der_seq(der_oid(tdx.OID_PPID), der_octets(b"\x50" * 16)),
                   der_seq(der_oid(tdx.OID_TCB), tcb),
                   der_seq(der_oid(tdx.OID_PCEID), der_octets(pce_id)),
                   der_seq(der_oid(tdx.OID_FMSPC), der_octets(fmspc)),
                   der_seq(der_oid(tdx.OID_SGX_TYPE), _der(0x0A, bytes([sgx_type]))))


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Intel")])


def _cert(subject, issuer, pub, signer, serial, exts=()):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(serial).not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER))
    for e in exts:
        b = b.add_extension(e, critical=False)
    return b.sign(signer, hashes.SHA256())


def _rs(sig_der: bytes) -> bytes:
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FakeIntel:
    cpu_svn: bytes = bytes([2] * 16)
    pce_svn: int = 13
    fmspc: bytes = bytes.fromhex("00906ed50000")
    pce_id: bytes = b"\x00\x00"
    tee_tcb_svn: bytes = bytes([5, 3] + [0] * 14)      # TDX module SVN 5, major version 3
    mr_signer_seam: bytes = b"\x5e" * 48
    seam_attributes: bytes = bytes(8)
    qe_mr_signer: bytes = b"\x9e" * 32
    qe_attributes: bytes = bytes.fromhex("11000000000000000000000000000000")
    qe_auth: bytes = b"\xa0" * 32
    keys: dict = field(default_factory=dict)

    def __post_init__(self):
        k = self.keys
        for n in ("root", "ca", "pck", "tcb", "ak"):
            k[n] = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert(_name("Intel SGX Root CA"), _name("Intel SGX Root CA"), k["root"].public_key(), k["root"], 1)
        self.ca = _cert(_name("Intel SGX PCK Platform CA"), _name("Intel SGX Root CA"), k["ca"].public_key(), k["root"], 2)
        self.pck = _cert(_name("Intel SGX PCK Certificate"), _name("Intel SGX PCK Platform CA"), k["pck"].public_key(), k["ca"], 3,
                         [x509.UnrecognizedExtension(x509.ObjectIdentifier(tdx.OID_SGX_EXT),
                                                     sgx_extension(self.fmspc, self.pce_id, self.cpu_svn, self.pce_svn))])
        self.tcb_cert = _cert(_name("Intel SGX TCB Signing"), _name("Intel SGX Root CA"), k["tcb"].public_key(), k["root"], 4)

    @property
    def pin(self) -> str:
        return tdx.spki_sha256(self.root)

    def chain_pem(self) -> bytes:
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (self.pck, self.ca, self.root))

    def issuer_chain_pem(self) -> bytes:
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (self.tcb_cert, self.root))

    def ak_raw(self, key=None) -> bytes:
        n = (key or self.keys["ak"]).public_key().public_numbers()
        return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

    def qe_report(self, ak_raw: bytes, isv_svn: int = 8, mr_signer: bytes | None = None) -> bytes:
        r = bytearray(tdx.SGX_REPORT_LEN)
        r[0:16] = self.cpu_svn
        r[48:64] = self.qe_attributes
        r[64:96] = b"\xe1" * 32
        r[128:160] = mr_signer or self.qe_mr_signer
        struct.pack_into("<HH", r, 256, 2, isv_svn)
        r[320:384] = hashlib.sha256(ak_raw + self.qe_auth).digest() + bytes(32)
        return bytes(r)

    def make_quote(self, report_data: bytes, *, mr_td: bytes = b"\x7d" * 48, rtmrs=None, td_attributes: bytes = bytes(8),
                   tee_tcb_svn: bytes | None = None, qe_isv_svn: int = 8, version: int = 4, tee_type: int = tdx.TEE_TYPE_TDX,
                   ak_key=None, certify_ak: bytes | None = None, chain_pem: bytes | None = None) -> bytes:
        rtmrs = rtmrs or [bytes([0x10 + i]) * 48 for i in range(4)]
        header = struct.pack("<HHI", version, tdx.ATT_KEY_ECDSA_P256, tee_type) + bytes(4) + QE_VENDOR_ID + bytes(20)
        body = struct.pack("<16s48s48s8s8s8s48s48s48s48s48s48s48s48s64s", tee_tcb_svn or self.tee_tcb_svn, b"\x5a" * 48,
                           self.mr_signer_seam, self.seam_attributes, td_attributes, bytes(8), mr_td, bytes(48), bytes(48),
                           bytes(48), *rtmrs, report_data.ljust(64, b"\0"))
        ak = ak_key or self.keys["ak"]
        ak_raw = self.ak_raw(ak)
        sig = _rs(ak.sign(header + body, ec.ECDSA(hashes.SHA256())))
        qe = self.qe_report(certify_ak if certify_ak is not None else ak_raw, qe_isv_svn)
        qe_sig = _rs(self.keys["pck"].sign(qe, ec.ECDSA(hashes.SHA256())))
        pem = (chain_pem if chain_pem is not None else self.chain_pem()) + b"\0"
        inner = struct.pack("<HI", tdx.CERT_DATA_PCK_CHAIN, len(pem)) + pem
        qe_cert = qe + qe_sig + struct.pack("<H", len(self.qe_auth)) + self.qe_auth + inner
        block = sig + ak_raw + struct.pack("<HI", tdx.CERT_DATA_QE_REPORT, len(qe_cert)) + qe_cert
        return header + body + struct.pack("<I", len(block)) + block

    # -- PCS
    def _signed(self, fld: str, obj: dict, signer=None) -> bytes:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        sig = _rs((signer or self.keys["tcb"]).sign(raw, ec.ECDSA(hashes.SHA256())))
        return b'{"' + fld.encode() + b'":' + raw + b',"signature":"' + sig.hex().encode() + b'"}'

    def tcb_info(self, now: float = FIXED_NOW, levels: list | None = None, module_levels: list | None = None) -> dict:
        comps = lambda v: [{"svn": v} for _ in range(16)]  # noqa: E731
        tdxc = lambda first, major: [{"svn": first}, {"svn": major}] + [{"svn": 0} for _ in range(14)]  # noqa: E731
        return {
            "id": "TDX", "version": 3, "issueDate": _iso(now - 86400), "nextUpdate": _iso(now + 30 * 86400),
            "fmspc": self.fmspc.hex(), "pceId": self.pce_id.hex(), "tcbType": 0, "tcbEvaluationDataNumber": 17,
            "tdxModule": {"mrsigner": self.mr_signer_seam.hex(), "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF"},
            "tdxModuleIdentities": [{"id": "TDX_03", "mrsigner": self.mr_signer_seam.hex(), "attributes": "0000000000000000",
                                     "attributesMask": "FFFFFFFFFFFFFFFF",
                                     "tcbLevels": module_levels or [{"tcb": {"isvsvn": 4}, "tcbDate": _iso(now - 86400), "tcbStatus": "UpToDate"},
                                                                    {"tcb": {"isvsvn": 2}, "tcbDate": _iso(now - 10 * 86400), "tcbStatus": "OutOfDate"}]}],
            "tcbLevels": levels or [
                {"tcb": {"sgxtcbcomponents": comps(2), "pcesvn": 13, "tdxtcbcomponents": tdxc(5, 3)},
                 "tcbDate": _iso(now - 86400), "tcbStatus": "UpToDate"},
                {"tcb": {"sgxtcbcomponents": comps(1), "pcesvn": 10, "tdxtcbcomponents": tdxc(3, 3)},
                 "tcbDate": _iso(now - 100 * 86400), "tcbStatus": "OutOfDate", "advisoryIDs": ["INTEL-SA-00001"]},
            ],
        }

    def qe_identity(self, now: float = FIXED_NOW, mr_signer: bytes | None = None) -> dict:
        return {"id": "TD_QE", "version": 2, "issueDate": _iso(now - 86400), "nextUpdate": _iso(now + 30 * 86400),
                "tcbEvaluationDataNumber": 17, "miscselect": "00000000", "miscselectMask": "FFFFFFFF",
                "attributes": "11000000000000000000000000000000", "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
                "mrsigner": (mr_signer or self.qe_mr_signer).hex(), "isvprodid": 2,
                "tcbLevels": [{"tcb": {"isvsvn": 8}, "tcbDate": _iso(now - 86400), "tcbStatus": "UpToDate"},
                              {"tcb": {"isvsvn": 6}, "tcbDate": _iso(now - 50 * 86400), "tcbStatus": "OutOfDate"}]}

    def tcb_info_response(self, **kw) -> tuple[bytes, bytes]:
        return self._signed("tcbInfo", self.tcb_info(**kw)), self.issuer_chain_pem()

    def qe_identity_response(self, **kw) -> tuple[bytes, bytes]:
        return self._signed("enclaveIdentity", self.qe_identity(**kw)), self.issuer_chain_pem()


class FakePcs:
    def __init__(self, intel: FakeIntel, tcb: tuple[bytes, bytes] | None = None, qe: tuple[bytes, bytes] | None = None):
        self.intel, self._tcb, self._qe, self.calls = intel, tcb, qe, []

    def tcb_info(self, fmspc: str):
        self.calls.append(("tcb", fmspc))
        return self._tcb or self.intel.tcb_info_response()

    def qe_identity(self):
        self.calls.append(("qe", None))
        return self._qe or self.intel.qe_identity_response()
