"""AMD SEV-SNP attester and verifier.

Attester (inside the CVM, Linux >= 6.7, root): configfs-tsm
  mkdir /sys/kernel/config/tsm/report/<x>; write 64-byte report_data to `inblob`;
  read `outblob` (ATTESTATION_REPORT, 0x4A0 bytes) and `auxblob` (optional
  host-provided certificate table).

Verifier:
  1. Parse the report (SEV-SNP ABI spec, Table "ATTESTATION_REPORT Structure").
  2. Pick the product (Milan / Genoa / Turin) from CPUID fields (report v3+) or
     configuration, and anchor ARK -> ASK -> VCEK, with the ARK pinned by the
     SHA-256 of its SubjectPublicKeyInfo. ARK/ASK ship with the package
     (attest/amd_roots/*.pem, from kdsintf.amd.com/vcek/v1/<product>/cert_chain);
     the VCEK comes from the evidence or AMD KDS (cached on disk).
  3. Check the VCEK's hwID / TCB extensions match the report's CHIP_ID /
     REPORTED_TCB, then verify the ECDSA-P384/SHA-384 signature over
     report[0x000:0x2A0].
  4. Check REPORT_DATA and VMPL; map MEASUREMENT, REPORTED_TCB, DEBUG to Claims.

SNP reports carry no timestamp: freshness comes from the single-use nonce that
is bound into REPORT_DATA, so `Claims.issued_at` is the verification time.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
import urllib.error
import urllib.request
import uuid
import warnings
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .base import AttestationError, Attester, Verifier
from .types import Claims, Evidence, Platform

REPORT_SIZE = 0x4A0
SIGNED_LEN = 0x2A0
SIG_ALGO_ECDSA_P384_SHA384 = 1
POLICY_DEBUG_BIT = 1 << 19

MILAN, GENOA, TURIN = "Milan", "Genoa", "Turin"

# SHA-256 of the ARK SubjectPublicKeyInfo (DER), from kdsintf.amd.com cert_chain.
ARK_SPKI_SHA256 = {
    MILAN: "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
    GENOA: "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831",
    TURIN: "4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08",
}

KDS_BASE = "https://kdsintf.amd.com/vcek/v1"

# VCEK X.509 extension OIDs (AMD "Versioned Chip Endorsement Key" spec).
OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
OID_FMC_SPL = "1.3.6.1.4.1.3704.1.3.9"
OID_HWID = "1.3.6.1.4.1.3704.1.4"
TCB_OIDS = {
    "bootloader": OID_BL_SPL,
    "tee": OID_TEE_SPL,
    "snp": OID_SNP_SPL,
    "microcode": OID_UCODE_SPL,
    "fmc": OID_FMC_SPL,
}
KDS_PARAMS = {"bootloader": "blSPL", "tee": "teeSPL", "snp": "snpSPL", "microcode": "ucodeSPL",
              "fmc": "fmcSPL"}

# GUIDs in the auxblob / extended-guest-request certificate table.
GUID_VCEK = uuid.UUID("63da758d-e664-4564-adc5-f4b93be8accd")


# --------------------------------------------------------------------------- report


def decode_tcb(raw: int, product: str) -> dict[str, int]:
    b = raw.to_bytes(8, "little")
    if product == TURIN:
        return {"fmc": b[0], "bootloader": b[1], "tee": b[2], "snp": b[3], "microcode": b[7]}
    return {"bootloader": b[0], "tee": b[1], "snp": b[6], "microcode": b[7]}


def encode_tcb(tcb: dict[str, int], product: str) -> int:
    b = bytearray(8)
    if product == TURIN:
        b[0], b[1], b[2], b[3] = tcb["fmc"], tcb["bootloader"], tcb["tee"], tcb["snp"]
    else:
        b[0], b[1], b[6] = tcb["bootloader"], tcb["tee"], tcb["snp"]
    b[7] = tcb["microcode"]
    return int.from_bytes(bytes(b), "little")


def product_from_cpuid(family: int, model: int) -> str | None:
    if family == 0x19:
        if model <= 0x0F:
            return MILAN
        if 0x10 <= model <= 0x1F or 0xA0 <= model <= 0xAF:
            return GENOA
    if family == 0x1A and model <= 0x1F:
        return TURIN
    return None


@dataclass(frozen=True)
class SnpReport:
    raw: bytes
    version: int
    guest_svn: int
    policy: int
    vmpl: int
    sig_algo: int
    current_tcb: int
    platform_info: int
    signing_key: int  # 0 = VCEK, 1 = VLEK
    mask_chip_key: bool
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    reported_tcb: int
    cpuid_fam: int
    cpuid_mod: int
    cpuid_step: int
    chip_id: bytes
    committed_tcb: int
    launch_tcb: int
    sig_r: int
    sig_s: int

    @property
    def debug(self) -> bool:
        return bool(self.policy & POLICY_DEBUG_BIT)

    @property
    def signed_bytes(self) -> bytes:
        return self.raw[:SIGNED_LEN]

    @classmethod
    def parse(cls, raw: bytes) -> "SnpReport":
        if len(raw) < REPORT_SIZE:
            raise AttestationError(f"SNP report too short ({len(raw)} < {REPORT_SIZE})")
        raw = bytes(raw[:REPORT_SIZE])
        u32 = lambda o: struct.unpack_from("<I", raw, o)[0]  # noqa: E731
        u64 = lambda o: struct.unpack_from("<Q", raw, o)[0]  # noqa: E731
        flags = u32(0x48)
        return cls(
            raw=raw,
            version=u32(0x00),
            guest_svn=u32(0x04),
            policy=u64(0x08),
            vmpl=u32(0x30),
            sig_algo=u32(0x34),
            current_tcb=u64(0x38),
            platform_info=u64(0x40),
            signing_key=(flags >> 2) & 0x7,
            mask_chip_key=bool(flags & 0x2),
            report_data=raw[0x50:0x90],
            measurement=raw[0x90:0xC0],
            host_data=raw[0xC0:0xE0],
            id_key_digest=raw[0xE0:0x110],
            author_key_digest=raw[0x110:0x140],
            report_id=raw[0x140:0x160],
            reported_tcb=u64(0x180),
            cpuid_fam=raw[0x188],
            cpuid_mod=raw[0x189],
            cpuid_step=raw[0x18A],
            chip_id=raw[0x1A0:0x1E0],
            committed_tcb=u64(0x1E0),
            launch_tcb=u64(0x1F0),
            sig_r=int.from_bytes(raw[0x2A0:0x2A0 + 72], "little"),
            sig_s=int.from_bytes(raw[0x2A0 + 72:0x2A0 + 144], "little"),
        )


def parse_cert_table(aux: bytes) -> dict[uuid.UUID, bytes]:
    """Parse the GUID-indexed certificate table (auxblob). Empty input -> {}."""
    out: dict[uuid.UUID, bytes] = {}
    off = 0
    while off + 24 <= len(aux):
        guid = uuid.UUID(bytes_le=aux[off:off + 16])
        c_off, c_len = struct.unpack_from("<II", aux, off + 16)
        if guid.int == 0:
            break
        if c_off + c_len > len(aux):
            raise AttestationError("malformed certificate table")
        out[guid] = aux[c_off:c_off + c_len]
        off += 24
    return out


# --------------------------------------------------------------------------- attester


class SnpAttester(Attester):
    """Obtain a report via configfs-tsm. Must run as root inside an SNP guest."""

    def __init__(self, tsm_root: str | Path = "/sys/kernel/config/tsm/report", privlevel: int = 0):
        self.tsm_root = Path(tsm_root)
        self.privlevel = privlevel

    def _create_entry(self, path: Path) -> None:
        path.mkdir()  # the kernel populates the attribute files

    def attest(self, report_data: bytes) -> Evidence:
        if len(report_data) > 64:
            raise ValueError("SNP report_data is at most 64 bytes")
        if not self.tsm_root.is_dir():
            raise AttestationError(
                f"{self.tsm_root} not found: needs Linux >= 6.7 with configfs-tsm, sev-guest "
                "loaded, configfs mounted, and an SNP guest"
            )
        entry = self.tsm_root / f"attestrag-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._create_entry(entry)
        try:
            provider = (entry / "provider").read_text().strip()
            if provider != "sev_guest":
                raise AttestationError(f"configfs-tsm provider is {provider!r}, expected 'sev_guest'")
            if self.privlevel:
                (entry / "privlevel").write_text(str(self.privlevel))
            (entry / "inblob").write_bytes(report_data.ljust(64, b"\0"))
            gen = (entry / "generation").read_text().strip()
            out = (entry / "outblob").read_bytes()
            aux_path = entry / "auxblob"
            try:
                aux = aux_path.read_bytes() if aux_path.exists() else b""
            except OSError:
                aux = b""  # host provided no certificates
            if (entry / "generation").read_text().strip() != gen:
                raise AttestationError("configfs-tsm entry modified concurrently; retry")
        finally:
            try:
                entry.rmdir()
            except OSError:
                pass
        certs = parse_cert_table(aux)
        chain = (certs[GUID_VCEK],) if GUID_VCEK in certs else ()
        return Evidence(Platform.SEV_SNP, out, b"", chain)


# --------------------------------------------------------------------------- certificates


class KdsClient:
    """ARK/ASK from the bundled PEMs; VCEKs from AMD KDS with an on-disk cache.

    KDS rate-limits aggressively, so a VCEK (immutable for a given chip + TCB) is
    fetched once and cached.
    """

    def __init__(self, cache_dir: str | Path | None = None, base_url: str = KDS_BASE,
                 timeout: float = 20.0, offline: bool = False):
        self.cache_dir = Path(cache_dir or Path.home() / ".cache" / "attestrag" / "kds")
        self.base_url = base_url
        self.timeout = timeout
        self.offline = offline

    def cert_chain(self, product: str) -> tuple[x509.Certificate, x509.Certificate]:
        """Return (ASK, ARK)."""
        try:
            pem = resources.files("attestrag.attest.amd_roots").joinpath(f"{product}.pem").read_bytes()
        except FileNotFoundError:
            pem = self._get(f"{self.base_url}/{product}/cert_chain")
        certs = x509.load_pem_x509_certificates(pem)
        if len(certs) != 2:
            raise AttestationError(f"unexpected {product} cert_chain length {len(certs)}")
        return certs[0], certs[1]

    def vcek_url(self, product: str, chip_id: bytes, tcb: dict[str, int]) -> str:
        hwid = chip_id[:8] if product == TURIN else chip_id
        keys = ["bootloader", "tee", "snp", "microcode"] + (["fmc"] if product == TURIN else [])
        q = "&".join(f"{KDS_PARAMS[k]}={tcb[k]:02d}" for k in keys)
        return f"{self.base_url}/{product}/{hwid.hex()}?{q}"

    def vcek(self, product: str, chip_id: bytes, tcb: dict[str, int]) -> x509.Certificate:
        return load_der_cert(self._get(self.vcek_url(product, chip_id, tcb)))

    def _get(self, url: str) -> bytes:
        path = self.cache_dir / hashlib.sha256(url.encode()).hexdigest()
        if path.exists():
            return path.read_bytes()
        if self.offline:
            raise AttestationError(f"not in KDS cache and offline: {url}")
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as r:
                data = r.read()
        except urllib.error.HTTPError as e:
            raise AttestationError(f"AMD KDS returned HTTP {e.code} for {url}") from e
        except OSError as e:
            raise AttestationError(f"AMD KDS unreachable: {e}") from e
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        return data


def load_der_cert(der: bytes) -> x509.Certificate:
    """Load an AMD certificate. AMD VCEKs carry serial number 0, which RFC 5280 forbids;
    `cryptography` currently only warns about it. The h200 golden test loads a real VCEK,
    so a release that starts rejecting them fails the suite instead of production."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*serial number.*", category=Warning)
        try:
            return x509.load_der_x509_certificate(der)
        except ValueError as e:
            raise AttestationError(f"cannot parse certificate (cryptography {_crypto_version()}): {e}") from e


def _crypto_version() -> str:
    import cryptography
    return cryptography.__version__


def _der_int(b: bytes) -> int:
    if len(b) < 3 or b[0] != 0x02 or b[1] != len(b) - 2:
        raise AttestationError("malformed INTEGER in VCEK extension")
    return int.from_bytes(b[2:], "big", signed=False)


def _ext(cert: x509.Certificate, oid: str) -> bytes | None:
    try:
        e = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
    except x509.ExtensionNotFound:
        return None
    return e.value.value  # UnrecognizedExtension: DER contents of extnValue


def spki_sha256(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------- verifier


class SnpVerifier(Verifier):
    def __init__(
        self,
        kds: KdsClient | None = None,
        product: str | None = None,
        ark_pins: dict[str, str] | None = None,
        max_vmpl: int = 0,
        clock=time.time,
    ):
        self.kds = kds or KdsClient()
        self.product = product
        self.ark_pins = ark_pins if ark_pins is not None else ARK_SPKI_SHA256
        self.max_vmpl = max_vmpl
        self.clock = clock

    def _product(self, r: SnpReport) -> str:
        p = product_from_cpuid(r.cpuid_fam, r.cpuid_mod) if r.version >= 3 else None
        if self.product and p and p != self.product:
            raise AttestationError(f"report CPUID says {p}, verifier configured for {self.product}")
        p = p or self.product
        if p is None:
            raise AttestationError("cannot determine product from report; configure product=")
        return p

    def _verify_chain(self, product: str, vcek: x509.Certificate) -> None:
        ask, ark = self.kds.cert_chain(product)
        pin = self.ark_pins.get(product)
        if pin is None or not hmac.compare_digest(spki_sha256(ark), pin):
            raise AttestationError(f"ARK for {product} does not match pinned key")
        now = self.clock()
        try:
            ark.verify_directly_issued_by(ark)
            ask.verify_directly_issued_by(ark)
            vcek.verify_directly_issued_by(ask)
        except (InvalidSignature, ValueError, TypeError) as e:
            raise AttestationError(f"AMD certificate chain invalid: {e}") from e
        for c in (ark, ask, vcek):
            if not (c.not_valid_before_utc.timestamp() <= now <= c.not_valid_after_utc.timestamp()):
                raise AttestationError(f"certificate {c.subject.rfc4514_string()} not valid now")

    def _check_vcek_binds_report(self, vcek: x509.Certificate, r: SnpReport, product: str,
                                 tcb: dict[str, int]) -> None:
        hw = _ext(vcek, OID_HWID)
        if hw is None:
            raise AttestationError("VCEK lacks hwID extension")
        if hw[:1] == b"\x04" and len(hw) >= 2 and hw[1] == len(hw) - 2:
            hw = hw[2:]  # tolerate OCTET STRING wrapping
        expect = r.chip_id[: len(hw)] if product == TURIN else r.chip_id
        if not hmac.compare_digest(hw, expect):
            raise AttestationError("VCEK hwID does not match report CHIP_ID")
        for name, value in tcb.items():
            raw = _ext(vcek, TCB_OIDS[name])
            if raw is None or _der_int(raw) != value:
                raise AttestationError(f"VCEK {name} SPL does not match REPORTED_TCB")

    def _vcek(self, ev: Evidence, product: str, r: SnpReport, tcb: dict[str, int]) -> x509.Certificate:
        for der in ev.cert_chain:
            c = load_der_cert(der)
            cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn and cn[0].value == "SEV-VCEK":
                return c
        if r.mask_chip_key or not any(r.chip_id):
            raise AttestationError("CHIP_ID masked and no VCEK supplied with evidence")
        return self.kds.vcek(product, r.chip_id, tcb)

    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        if evidence.platform is not Platform.SEV_SNP:
            raise AttestationError("not SEV-SNP evidence")
        r = SnpReport.parse(evidence.report)
        if r.version < 2:
            raise AttestationError(f"unsupported report version {r.version}")
        if r.sig_algo != SIG_ALGO_ECDSA_P384_SHA384:
            raise AttestationError(f"unsupported signature algorithm {r.sig_algo}")
        if r.signing_key != 0:
            raise AttestationError("VLEK-signed reports not supported yet")
        product = self._product(r)
        tcb = decode_tcb(r.reported_tcb, product)

        vcek = self._vcek(evidence, product, r, tcb)
        self._verify_chain(product, vcek)
        self._check_vcek_binds_report(vcek, r, product, tcb)
        pub = vcek.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
            raise AttestationError("VCEK is not an ECDSA P-384 key")
        try:
            pub.verify(encode_dss_signature(r.sig_r, r.sig_s), r.signed_bytes, ec.ECDSA(hashes.SHA384()))
        except InvalidSignature as e:
            raise AttestationError("bad report signature") from e

        if not hmac.compare_digest(r.report_data, expected_report_data.ljust(64, b"\0")):
            raise AttestationError("report_data does not match expected nonce/key binding")
        if r.vmpl > self.max_vmpl:
            raise AttestationError(f"report requested at VMPL{r.vmpl} > {self.max_vmpl}")

        return Claims(
            platform=Platform.SEV_SNP,
            measurement=r.measurement.hex(),
            tcb=tcb,
            report_data=expected_report_data,
            debug=r.debug,
            issued_at=self.clock(),
            signer=f"amd-{product.lower()}-vcek",
            extra={
                "product": product,
                "report_version": str(r.version),
                "guest_policy": hex(r.policy),
                "vmpl": str(r.vmpl),
                "guest_svn": str(r.guest_svn),
                "host_data": r.host_data.hex(),
                "id_key_digest": r.id_key_digest.hex(),
                "chip_id": r.chip_id.hex(),
                "current_tcb": hex(r.current_tcb),
                "committed_tcb": hex(r.committed_tcb),
                "launch_tcb": hex(r.launch_tcb),
            },
        )
