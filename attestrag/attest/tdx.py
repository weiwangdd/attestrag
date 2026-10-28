"""Intel TDX attester and verifier (DCAP quote format version 4, ECDSA-P256).

Attester (inside the TD, Linux >= 6.7, root): configfs-tsm exactly as for SNP
  (provider `tdx_guest`); the kernel asks the host's quote generation service through
  the GetQuote TDVMCALL and `outblob` is the finished quote.

Verifier (Intel "TDX DCAP Quoting Library API", quote v4; PCS API v4):
  1. Parse: header (48 B), TD report body (584 B), signature block: ECDSA-P256 signature
     over header || body, attestation key, QE certification data (type 6): the Quoting
     Enclave's SGX report, its signature by the PCK certificate, the QE authentication
     data and the PCK certificate chain (type 5, PEM: PCK -> Platform/Processor CA -> root).
  2. Anchor PCK -> intermediate -> Intel SGX Root CA, root pinned by the SHA-256 of its
     SubjectPublicKeyInfo; validity dates against the verifier clock.
  3. QE report signed by the PCK key; QE report_data = SHA-256(attestation key || QE auth
     data) || 32 zero bytes; quote signed by the attestation key. That ties the quote to
     the platform certificate.
  4. TCB: the PCK's SGX extension (FMSPC, PCE id, CPU SVN components, PCE SVN) against
     Intel PCS TCB info for that FMSPC, and the TD report's TEE_TCB_SVN against the TDX
     components of the matching level; TDX module identity (MRSIGNERSEAM, attributes,
     module SVN) and QE identity (MRSIGNER, ISV prod id, attributes, ISV SVN) from PCS.
     PCS responses are signed JSON (TCB signing certificate -> the same root); cached.
  5. REPORT_DATA (64 B) must equal the expected binding; DEBUG = TD attribute bit 0.
     MRTD becomes `measurement`; RTMR0..3, MRSEAM, attributes, TCB status, dates and
     advisory ids go to `extra`; `tcb` carries integers the policy can bound (status
     rank, PCE SVN, TDX module SVN and major version, QE SVN, TCB evaluation number).

Not done: PCK CRLs and the root CA CRL (PCS /pckcrl), quote version 5.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .base import AttestationError, Attester, Verifier
from .types import Claims, Evidence, Platform

QUOTE_VERSION = 4
ATT_KEY_ECDSA_P256 = 2
TEE_TYPE_TDX = 0x81
HEADER_LEN = 48
TD_REPORT_LEN = 584
SIGNED_LEN = HEADER_LEN + TD_REPORT_LEN
SGX_REPORT_LEN = 384
CERT_DATA_PCK_CHAIN = 5
CERT_DATA_QE_REPORT = 6
TD_ATTR_DEBUG = 1 << 0

# SHA-256 of the SubjectPublicKeyInfo of "Intel SGX Root CA" (certificates.trustedservices.intel.com,
# Intel_SGX_Provisioning_Certification_RootCA.pem, valid to 2049).
INTEL_ROOT_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"
PCS_BASE = "https://api.trustedservices.intel.com/tdx/certification/v4"

OID_SGX_EXT = "1.2.840.113741.1.13.1"
OID_PPID, OID_TCB, OID_PCEID, OID_FMSPC, OID_SGX_TYPE = (OID_SGX_EXT + s for s in (".1", ".2", ".3", ".4", ".5"))
OID_PCESVN, OID_CPUSVN = OID_TCB + ".17", OID_TCB + ".18"

TCB_STATUS_RANK = {"UpToDate": 4, "SWHardeningNeeded": 3, "ConfigurationNeeded": 2,
                   "ConfigurationAndSWHardeningNeeded": 1, "OutOfDate": 0, "OutOfDateConfigurationNeeded": 0,
                   "Revoked": -1}


def tcb_rank(status: str) -> int:
    return TCB_STATUS_RANK.get(status, -1)


# --------------------------------------------------------------------------- quote parsing

@dataclass(frozen=True)
class TdReport:
    tee_tcb_svn: bytes
    mr_seam: bytes
    mr_signer_seam: bytes
    seam_attributes: bytes
    td_attributes: bytes
    xfam: bytes
    mr_td: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    rtmr: tuple[bytes, bytes, bytes, bytes]
    report_data: bytes

    @classmethod
    def parse(cls, b: bytes) -> "TdReport":
        if len(b) != TD_REPORT_LEN:
            raise AttestationError(f"TD report body is {len(b)} bytes, expected {TD_REPORT_LEN}")
        f = struct.unpack("<16s48s48s8s8s8s48s48s48s48s48s48s48s48s64s", b)
        return cls(*f[:10], (f[10], f[11], f[12], f[13]), f[14])

    @property
    def debug(self) -> bool:
        return bool(self.td_attributes[0] & TD_ATTR_DEBUG)


@dataclass(frozen=True)
class SgxReportBody:
    cpu_svn: bytes
    misc_select: int
    attributes: bytes
    mr_enclave: bytes
    mr_signer: bytes
    isv_prod_id: int
    isv_svn: int
    report_data: bytes

    @classmethod
    def parse(cls, b: bytes) -> "SgxReportBody":
        if len(b) != SGX_REPORT_LEN:
            raise AttestationError(f"QE report is {len(b)} bytes, expected {SGX_REPORT_LEN}")
        return cls(b[0:16], struct.unpack_from("<I", b, 16)[0], b[48:64], b[64:96], b[128:160],
                   struct.unpack_from("<H", b, 256)[0], struct.unpack_from("<H", b, 258)[0], b[320:384])


@dataclass(frozen=True)
class TdxQuote:
    version: int
    att_key_type: int
    tee_type: int
    qe_vendor_id: bytes
    user_data: bytes
    td: TdReport
    signed_bytes: bytes
    signature: bytes          # r || s, 64 bytes
    attestation_key: bytes    # x || y, 64 bytes
    qe_report_raw: bytes
    qe_report: SgxReportBody
    qe_report_signature: bytes
    qe_auth_data: bytes
    pck_chain_pem: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "TdxQuote":
        if len(raw) < SIGNED_LEN + 4:
            raise AttestationError("quote too short")
        version, att_key_type, tee_type = struct.unpack_from("<HHI", raw, 0)
        qe_vendor_id, user_data = raw[12:28], raw[28:48]
        td = TdReport.parse(raw[HEADER_LEN:SIGNED_LEN])
        sig_len = struct.unpack_from("<I", raw, SIGNED_LEN)[0]
        sig = raw[SIGNED_LEN + 4: SIGNED_LEN + 4 + sig_len]
        if len(sig) != sig_len or sig_len < 64 + 64 + 6:
            raise AttestationError("quote signature block truncated")
        signature, ak = sig[:64], sig[64:128]
        ctype, csize = struct.unpack_from("<HI", sig, 128)
        cdata = sig[134:134 + csize]
        if len(cdata) != csize:
            raise AttestationError("quote certification data truncated")
        if ctype != CERT_DATA_QE_REPORT:
            raise AttestationError(f"unsupported certification data type {ctype} (quote v4 carries the QE report as type 6)")
        if len(cdata) < SGX_REPORT_LEN + 64 + 2:
            raise AttestationError("QE certification data truncated")
        qe_raw = cdata[:SGX_REPORT_LEN]
        qe_sig = cdata[SGX_REPORT_LEN:SGX_REPORT_LEN + 64]
        off = SGX_REPORT_LEN + 64
        auth_len = struct.unpack_from("<H", cdata, off)[0]
        auth = cdata[off + 2: off + 2 + auth_len]
        off += 2 + auth_len
        if len(cdata) < off + 6:
            raise AttestationError("QE certification data truncated")
        itype, isize = struct.unpack_from("<HI", cdata, off)
        pem = cdata[off + 6: off + 6 + isize]
        if itype != CERT_DATA_PCK_CHAIN or len(pem) != isize:
            raise AttestationError(f"expected a PCK certificate chain (type 5) in the quote, got type {itype}")
        return cls(version, att_key_type, tee_type, qe_vendor_id, user_data, td, raw[:SIGNED_LEN], signature, ak,
                   qe_raw, SgxReportBody.parse(qe_raw), qe_sig, auth, pem.rstrip(b"\0"))


# --------------------------------------------------------------------------- DER (SGX extension)

def _der_tlv(b: bytes, i: int) -> tuple[int, bytes, int]:
    tag, ln = b[i], b[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + ln], i + ln


def _der_oid(body: bytes) -> str:
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    v = 0
    for c in body[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)


def _der_value(tag: int, body: bytes):
    if tag == 0x02 or tag == 0x0A:        # INTEGER / ENUMERATED
        return int.from_bytes(body, "big", signed=True)
    if tag == 0x04:                       # OCTET STRING
        return body
    if tag == 0x30:                       # SEQUENCE of (OID, value)
        return _der_pairs(body)
    return body


def _der_pairs(body: bytes) -> dict:
    out, i = {}, 0
    while i < len(body):
        tag, item, i = _der_tlv(body, i)
        if tag != 0x30:
            raise AttestationError("malformed SGX extension")
        t1, oid_body, j = _der_tlv(item, 0)
        t2, val, _ = _der_tlv(item, j)
        out[_der_oid(oid_body)] = _der_value(t2, val)
    return out


@dataclass(frozen=True)
class PckInfo:
    fmspc: str
    pce_id: str
    cpu_svn: bytes            # 16 components
    pce_svn: int
    sgx_type: int

    @classmethod
    def from_cert(cls, cert: x509.Certificate) -> "PckInfo":
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(OID_SGX_EXT)).value.value
        except x509.ExtensionNotFound:
            raise AttestationError("PCK certificate lacks the SGX extension") from None
        tag, body, _ = _der_tlv(ext, 0)
        if tag != 0x30:
            raise AttestationError("malformed SGX extension")
        d = _der_pairs(body)
        try:
            tcb = d[OID_TCB]
            comps = bytes(tcb[f"{OID_TCB}.{i}"] for i in range(1, 17))
            return cls(d[OID_FMSPC].hex(), d[OID_PCEID].hex(), comps, int(tcb[OID_PCESVN]), int(d.get(OID_SGX_TYPE, 0)))
        except (KeyError, TypeError, ValueError) as e:
            raise AttestationError(f"SGX extension incomplete: {e}") from None


# --------------------------------------------------------------------------- Intel PCS

class PcsClient:
    """TCB info and QE identity from Intel PCS v4 with an on-disk cache of body + issuer chain."""

    def __init__(self, cache_dir: str | Path | None = None, base_url: str = PCS_BASE,
                 timeout: float = 20.0, offline: bool = False):
        self.cache_dir = Path(cache_dir or Path.home() / ".cache" / "attestrag" / "pcs")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.offline = offline

    def tcb_info(self, fmspc: str) -> tuple[bytes, bytes]:
        return self._get(f"{self.base_url}/tcb?fmspc={fmspc}", "TCB-Info-Issuer-Chain")

    def qe_identity(self) -> tuple[bytes, bytes]:
        return self._get(f"{self.base_url}/qe/identity", "SGX-Enclave-Identity-Issuer-Chain")

    def _get(self, url: str, chain_header: str) -> tuple[bytes, bytes]:
        path = self.cache_dir / (hashlib.sha256(url.encode()).hexdigest() + ".json")
        if path.exists():
            d = json.loads(path.read_text())
            return base64.b64decode(d["body"]), d["chain"].encode()
        if self.offline:
            raise AttestationError(f"not in PCS cache and offline: {url}")
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "attestrag"}), timeout=self.timeout) as r:
                body = r.read()
                chain = urllib.parse.unquote(r.headers.get(chain_header, ""))
        except (urllib.error.URLError, OSError) as e:
            raise AttestationError(f"Intel PCS fetch failed: {url}: {e}") from e
        if not chain:
            raise AttestationError(f"Intel PCS response lacks {chain_header}")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"url": url, "body": base64.b64encode(body).decode(), "chain": chain}))
        tmp.replace(path)
        return body, chain.encode()


def _raw_json_field(body: bytes, field: str) -> bytes:
    """The exact bytes of the top-level `field` object: PCS signs them as served, not re-serialised."""
    key = f'"{field}":'.encode()
    i = body.find(key)
    if i < 0:
        raise AttestationError(f"PCS response lacks {field}")
    i += len(key)
    while body[i:i + 1].isspace():
        i += 1
    if body[i:i + 1] != b"{":
        raise AttestationError(f"PCS {field} is not an object")
    depth, j, in_str, esc = 0, i, False, False
    while j < len(body):
        c = body[j:j + 1]
        if in_str:
            if esc:
                esc = False
            elif c == b"\\":
                esc = True
            elif c == b'"':
                in_str = False
        elif c == b'"':
            in_str = True
        elif c == b"{":
            depth += 1
        elif c == b"}":
            depth -= 1
            if depth == 0:
                return body[i:j + 1]
        j += 1
    raise AttestationError(f"PCS {field} unterminated")


def spki_sha256(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives import serialization
    return hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _p256_verify(pub, sig_rs: bytes, data: bytes, what: str) -> None:
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise AttestationError(f"{what}: key is not ECDSA P-256")
    if len(sig_rs) != 64:
        raise AttestationError(f"{what}: signature is {len(sig_rs)} bytes")
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig_rs[:32], "big"), int.from_bytes(sig_rs[32:], "big")),
                   data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise AttestationError(f"{what}: bad signature") from None


def _iso(ts: str) -> float:
    import datetime as dt
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


# --------------------------------------------------------------------------- attester

class TdxAttester(Attester):
    """Obtain a quote via configfs-tsm. Must run as root inside a TD."""

    def __init__(self, tsm_root: str | Path = "/sys/kernel/config/tsm/report"):
        self.tsm_root = Path(tsm_root)

    def attest(self, report_data: bytes) -> Evidence:
        if len(report_data) > 64:
            raise ValueError("TDX report_data is at most 64 bytes")
        if not self.tsm_root.is_dir():
            raise AttestationError(f"{self.tsm_root} not found: needs Linux >= 6.7 with configfs-tsm, tdx_guest and a TD")
        entry = self.tsm_root / f"attestrag-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        entry.mkdir()
        try:
            provider = (entry / "provider").read_text().strip()
            if provider != "tdx_guest":
                raise AttestationError(f"configfs-tsm provider is {provider!r}, expected 'tdx_guest'")
            (entry / "inblob").write_bytes(report_data.ljust(64, b"\0"))
            gen = (entry / "generation").read_text().strip()
            out = (entry / "outblob").read_bytes()
            if (entry / "generation").read_text().strip() != gen:
                raise AttestationError("configfs-tsm entry modified concurrently; retry")
        finally:
            try:
                entry.rmdir()
            except OSError:
                pass
        return Evidence(Platform.TDX, out, b"", ())


# --------------------------------------------------------------------------- verifier

class TdxVerifier(Verifier):
    def __init__(self, pcs: PcsClient | None = None, root_pin: str = INTEL_ROOT_SPKI_SHA256, clock=time.time):
        self.pcs = pcs or PcsClient()
        self.root_pin = root_pin
        self.clock = clock

    # -- certificates
    def _chain(self, pem: bytes) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
        try:
            certs = x509.load_pem_x509_certificates(pem)
        except ValueError as e:
            raise AttestationError(f"PCK certificate chain unreadable: {e}") from None
        if len(certs) != 3:
            raise AttestationError(f"PCK certificate chain has {len(certs)} certificates, expected 3")
        return certs[0], certs[1], certs[2]

    def _anchor(self, *certs: x509.Certificate) -> None:
        """certs[-1] is the root: pinned, self-signed; each other certificate issued by the next."""
        root = certs[-1]
        if not hmac.compare_digest(spki_sha256(root), self.root_pin):
            raise AttestationError("root certificate does not match the pinned Intel SGX Root CA")
        now = self.clock()
        try:
            root.verify_directly_issued_by(root)
            for c, issuer in zip(certs, certs[1:]):
                c.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError) as e:
            raise AttestationError(f"Intel certificate chain invalid: {e}") from e
        for c in certs:
            if not (c.not_valid_before_utc.timestamp() <= now <= c.not_valid_after_utc.timestamp()):
                raise AttestationError(f"certificate {c.subject.rfc4514_string()} not valid now")

    def _signed_json(self, body: bytes, field: str, chain_pem: bytes, now: float) -> dict:
        try:
            certs = x509.load_pem_x509_certificates(chain_pem)
        except ValueError as e:
            raise AttestationError(f"PCS issuer chain unreadable: {e}") from None
        if len(certs) != 2:
            raise AttestationError(f"PCS issuer chain has {len(certs)} certificates, expected 2")
        self._anchor(certs[0], certs[1])
        try:
            d = json.loads(body)
            sig = bytes.fromhex(d["signature"])
        except (ValueError, KeyError, TypeError) as e:
            raise AttestationError(f"PCS {field} response malformed: {e}") from None
        _p256_verify(certs[0].public_key(), sig, _raw_json_field(body, field), f"PCS {field}")
        info = d[field]
        if not (_iso(info["issueDate"]) <= now <= _iso(info["nextUpdate"])):
            raise AttestationError(f"PCS {field} not valid now (issued {info['issueDate']}, next update {info['nextUpdate']})")
        return info

    # -- TCB
    @staticmethod
    def _components_ok(have: bytes, want: list[dict], skip: tuple[int, ...] = ()) -> bool:
        return all(i in skip or have[i] >= int(c.get("svn", 0)) for i, c in enumerate(want[:16]))

    def _tcb_level(self, info: dict, pck: PckInfo, td: TdReport) -> dict:
        """Intel's matching order: the first level (newest first) whose SGX components and PCE SVN the
        PCK satisfies, then from there the first whose TDX components TEE_TCB_SVN satisfies. Index 0 of
        TEE_TCB_SVN is the TDX module's own SVN (checked against the module identity) and index 1 its
        major version, so those two are not compared here."""
        levels = info.get("tcbLevels", [])
        k = next((i for i, lv in enumerate(levels)
                  if self._components_ok(pck.cpu_svn, lv["tcb"]["sgxtcbcomponents"]) and pck.pce_svn >= int(lv["tcb"]["pcesvn"])), None)
        if k is None:
            raise AttestationError("PCK TCB below every level in Intel's TCB info (platform TCB unknown or revoked)")
        for lv in levels[k:]:
            if self._components_ok(td.tee_tcb_svn, lv["tcb"].get("tdxtcbcomponents", []), skip=(0, 1)):
                return lv
        raise AttestationError("TD TEE_TCB_SVN below every TDX level in Intel's TCB info")

    def _module(self, info: dict, td: TdReport) -> tuple[str, str]:
        """TDX module identity for the running module's major version: (status, identity id)."""
        major = td.tee_tcb_svn[1]
        ident = next((m for m in info.get("tdxModuleIdentities", []) if m.get("id") == f"TDX_{major:02d}"), None)
        if ident is None:
            if major == 0 and "tdxModule" in info:   # TDX 1.0: single module descriptor, no SVN levels
                m = info["tdxModule"]
                self._module_match(m, td)
                return "UpToDate", "TDX_00"
            raise AttestationError(f"no TDX module identity for major version {major} in Intel's TCB info")
        self._module_match(ident, td)
        for lv in ident.get("tcbLevels", []):
            if td.tee_tcb_svn[0] >= int(lv["tcb"]["isvsvn"]):
                return lv["tcbStatus"], ident["id"]
        raise AttestationError("TDX module SVN below every level of its identity")

    @staticmethod
    def _module_match(m: dict, td: TdReport) -> None:
        if td.mr_signer_seam != bytes.fromhex(m["mrsigner"]):
            raise AttestationError("MRSIGNERSEAM does not match the TDX module identity")
        attrs, mask = bytes.fromhex(m["attributes"]), bytes.fromhex(m["attributesMask"])
        if bytes(a & b for a, b in zip(td.seam_attributes, mask)) != attrs:
            raise AttestationError("SEAM attributes do not match the TDX module identity")

    def _qe(self, ident: dict, qe: SgxReportBody) -> str:
        if ident.get("id") != "TD_QE":
            raise AttestationError(f"QE identity is for {ident.get('id')!r}, expected TD_QE")
        if qe.mr_signer != bytes.fromhex(ident["mrsigner"]):
            raise AttestationError("QE MRSIGNER does not match Intel's QE identity")
        if qe.isv_prod_id != int(ident["isvprodid"]):
            raise AttestationError("QE ISV product id does not match Intel's QE identity")
        if (qe.misc_select & int(ident["miscselectMask"], 16)) != int(ident["miscselect"], 16):
            raise AttestationError("QE MISCSELECT does not match Intel's QE identity")
        attrs, mask = bytes.fromhex(ident["attributes"]), bytes.fromhex(ident["attributesMask"])
        if bytes(a & b for a, b in zip(qe.attributes, mask)) != attrs:
            raise AttestationError("QE attributes do not match Intel's QE identity")
        for lv in ident.get("tcbLevels", []):
            if qe.isv_svn >= int(lv["tcb"]["isvsvn"]):
                return lv["tcbStatus"]
        raise AttestationError("QE ISV SVN below every level of Intel's QE identity")

    # -- entry point
    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        if evidence.platform is not Platform.TDX:
            raise AttestationError("not TDX evidence")
        q = TdxQuote.parse(evidence.report)
        if q.version != QUOTE_VERSION:
            raise AttestationError(f"unsupported quote version {q.version}")
        if q.att_key_type != ATT_KEY_ECDSA_P256:
            raise AttestationError(f"unsupported attestation key type {q.att_key_type}")
        if q.tee_type != TEE_TYPE_TDX:
            raise AttestationError(f"quote is not for TDX (tee_type {q.tee_type:#x})")
        pck, inter, root = self._chain(q.pck_chain_pem)
        self._anchor(pck, inter, root)
        _p256_verify(pck.public_key(), q.qe_report_signature, q.qe_report_raw, "QE report")
        expect = hashlib.sha256(q.attestation_key + q.qe_auth_data).digest() + bytes(32)
        if not hmac.compare_digest(q.qe_report.report_data, expect):
            raise AttestationError("QE report does not certify this attestation key")
        try:
            ak = ec.EllipticCurvePublicNumbers(int.from_bytes(q.attestation_key[:32], "big"),
                                               int.from_bytes(q.attestation_key[32:], "big"), ec.SECP256R1()).public_key()
        except ValueError:
            raise AttestationError("attestation key is not a point on P-256") from None
        _p256_verify(ak, q.signature, q.signed_bytes, "quote")

        now = self.clock()
        info_pck = PckInfo.from_cert(pck)
        body, chain = self.pcs.tcb_info(info_pck.fmspc)
        tcb_info = self._signed_json(body, "tcbInfo", chain, now)
        if tcb_info.get("id") != "TDX":
            raise AttestationError(f"TCB info is for {tcb_info.get('id')!r}, expected TDX")
        if tcb_info.get("fmspc", "").lower() != info_pck.fmspc or tcb_info.get("pceId", "").lower() != info_pck.pce_id:
            raise AttestationError("TCB info FMSPC/PCE id do not match the PCK certificate")
        level = self._tcb_level(tcb_info, info_pck, q.td)
        module_status, module_id = self._module(tcb_info, q.td)
        body, chain = self.pcs.qe_identity()
        qe_status = self._qe(self._signed_json(body, "enclaveIdentity", chain, now), q.qe_report)
        statuses = {"tcb": level["tcbStatus"], "tdx_module": module_status, "qe": qe_status}
        overall = min(statuses, key=lambda k: tcb_rank(statuses[k]))

        if not hmac.compare_digest(q.td.report_data, expected_report_data.ljust(64, b"\0")):
            raise AttestationError("report_data does not match expected nonce/key binding")

        ca = inter.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return Claims(
            platform=Platform.TDX,
            measurement=q.td.mr_td.hex(),
            tcb={"status": tcb_rank(statuses[overall]), "pcesvn": info_pck.pce_svn,
                 "tdx_module_svn": q.td.tee_tcb_svn[0], "tdx_module_major": q.td.tee_tcb_svn[1],
                 "qe_svn": q.qe_report.isv_svn, "tcb_evaluation": int(tcb_info.get("tcbEvaluationDataNumber", 0))},
            report_data=expected_report_data,
            debug=q.td.debug,
            issued_at=now,
            signer="intel-sgx-root-ca",
            extra={
                "tcb_status": statuses[overall], "tcb_status_platform": level["tcbStatus"],
                "tcb_status_module": module_status, "tcb_status_qe": qe_status,
                "tcb_date": level.get("tcbDate", ""), "advisory_ids": ",".join(level.get("advisoryIDs", [])),
                "fmspc": info_pck.fmspc, "pce_id": info_pck.pce_id, "pck_ca": ca[0].value if ca else "",
                "tdx_module": module_id, "tee_tcb_svn": q.td.tee_tcb_svn.hex(),
                "mr_seam": q.td.mr_seam.hex(), "mr_signer_seam": q.td.mr_signer_seam.hex(),
                "td_attributes": q.td.td_attributes.hex(), "xfam": q.td.xfam.hex(),
                "mr_config_id": q.td.mr_config_id.hex(), "mr_owner": q.td.mr_owner.hex(), "mr_owner_config": q.td.mr_owner_config.hex(),
                **{f"rtmr{i}": r.hex() for i, r in enumerate(q.td.rtmr)},
                "qe_vendor_id": q.qe_vendor_id.hex(), "qe_mr_enclave": q.qe_report.mr_enclave.hex(),
            },
        )
