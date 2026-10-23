"""NVIDIA reference measurements (RIM) and certificate revocation (OCSP) for GPU attestation.

A GPU report carries 64 DMTF measurement blocks. Which values are the right ones for a given
driver and VBIOS is published by NVIDIA as two Reference Integrity Manifests (SWID tags, TCG
RIM binding, signed with an enveloped XML-DSig whose certificate chain ends in the NVIDIA
CoRIM signing Root CA): one for the driver (`NV_GPU_DRIVER_GH100_<version>`) and one for the
VBIOS (`NV_GPU_VBIOS_<project>_<sku>_<chip>_<vbios>`). Each manifest lists, per index, an
"active" flag and one or more alternative SHA-384 values; the two manifests cover disjoint
index sets. Manifest index k corresponds to the k-th measurement block of the report (the
blocks are counted from 0 here; the SPDM index byte starts at 1).

Revocation: NVIDIA runs an OCSP responder for the device-identity and RIM-signing hierarchies.
Responses are signed by a delegated responder certificate (id-kp-OCSPSigning) issued by the
certificate's own issuer and carry the request nonce.

Both services are optional for the verifier: without them the policy's pinned composite
digest is the only reference. With them, a report whose blocks disagree with the published
manifests fails verification even if the digest were allowed, and a revoked certificate
fails the chain. Responses and manifests are cached on disk (manifests are immutable per id;
OCSP responses until their nextUpdate).

Mirrors the checks of NVIDIA's local GPU verifier (nvtrust) without depending on it.
XML signature verification needs the optional `signxml` package (`pip install attestrag[nvidia]`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from .base import AttestationError

RIM_BASE = "https://rim.attestation.nvidia.com/v1/rim/"
OCSP_URL = "https://ocsp.ndis.nvidia.com/"
SWID_NS = "{http://standards.iso.org/iso/19770/-2/2015/schema.xsd}"
DSIG_NS = "{http://www.w3.org/2000/09/xmldsig#}"
HASH_NS = "{http://www.w3.org/2001/04/xmlenc#sha384}"
NVDEC_DISABLED = 0x55          # opaque field "nvdec0_status": manifest index 35 is not measured then
NVDEC_INDEX = 35


def driver_rim_id(driver_version: str, arch: str = "GH100") -> str:
    return f"NV_GPU_DRIVER_{arch}_{driver_version.strip()}"


def vbios_rim_id(project: str, project_sku: str, chip_sku: str, vbios_version: str) -> str:
    parts = [s.strip().strip("\0").upper() for s in (project, project_sku, chip_sku)]
    return "NV_GPU_VBIOS_" + "_".join(parts) + "_" + vbios_version.replace(".", "").upper()


def verify_chain(chain: Sequence[x509.Certificate], roots: dict[bytes, x509.Certificate], now: float) -> x509.Certificate:
    """Leaf-first chain: every certificate valid at `now` and signed by the next; the last one pinned."""
    if not chain:
        raise AttestationError("empty certificate chain")
    for i, cert in enumerate(chain):
        nb, na = cert.not_valid_before_utc.timestamp(), cert.not_valid_after_utc.timestamp()
        if not (nb <= now <= na):
            raise AttestationError(f"certificate {i} ({cert.subject.rfc4514_string()}) not valid now")
        issuer = chain[i + 1] if i + 1 < len(chain) else None
        if issuer is None:
            if cert.public_bytes(Encoding.DER) not in roots:
                raise AttestationError("certificate chain does not end in a pinned NVIDIA root")
            issuer = cert
        _check_signed_by(cert, issuer, f"certificate {i}")
    return chain[0]


def _check_signed_by(cert: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    pub = issuer.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise AttestationError(f"{what}: issuer key is not ECDSA")
    try:
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"{what} signature invalid: {e}") from e


# --- reference manifests -------------------------------------------------------------------

@dataclass(frozen=True)
class RimEntry:
    index: int
    active: bool
    size: int
    alternatives: tuple[bytes, ...]
    name: str


@dataclass(frozen=True)
class ReferenceManifest:
    xml: bytes
    version: str                      # Meta colloquialVersion, lower-cased (driver version / VBIOS version)
    product: str
    entries: dict[int, RimEntry]
    cert_chain: tuple[x509.Certificate, ...]   # leaf first, as listed in KeyInfo (NVIDIA includes the root last)

    @classmethod
    def parse(cls, xml: bytes) -> "ReferenceManifest":
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as e:
            raise AttestationError(f"RIM is not well-formed XML: {e}") from e
        if root.tag != SWID_NS + "SoftwareIdentity":
            raise AttestationError("RIM is not a SWID SoftwareIdentity")
        meta = root.find(SWID_NS + "Meta")
        payload = root.find(SWID_NS + "Payload")
        if meta is None or payload is None:
            raise AttestationError("RIM lacks Meta or Payload")
        version = meta.attrib.get("colloquialVersion", "").strip().lower()
        if not version:
            raise AttestationError("RIM has no colloquialVersion")
        entries: dict[int, RimEntry] = {}
        for e in payload:
            if e.attrib.get("type") != "Measurement":
                continue
            idx = int(e.attrib["index"])
            if idx in entries:
                raise AttestationError(f"RIM lists index {idx} twice")
            n = int(e.attrib.get("alternatives", "1"))
            alts = tuple(bytes.fromhex(e.attrib[HASH_NS + f"Hash{k}"]) for k in range(n))
            entries[idx] = RimEntry(idx, e.attrib.get("active", "True") != "False", int(e.attrib.get("size", "48")),
                                    alts, e.attrib.get("name", f"Measurement_{idx}"))
        if not entries:
            raise AttestationError("RIM carries no measurements")
        certs = tuple(x509.load_der_x509_certificate(base64.b64decode("".join(c.text.split())))
                      for c in root.iter(DSIG_NS + "X509Certificate") if c.text)
        if not certs:
            raise AttestationError("RIM carries no signing certificate")
        return cls(xml, version, meta.attrib.get("product", ""), entries, certs)

    def active(self) -> dict[int, RimEntry]:
        return {i: e for i, e in self.entries.items() if e.active}

    def verify(self, roots: dict[bytes, x509.Certificate], now: float, ocsp_client: "OcspClient | None" = None) -> x509.Certificate:
        """Chain to a pinned CoRIM root (and OCSP, if given), then the enveloped XML signature with the leaf key."""
        leaf = verify_chain(self.cert_chain, roots, now)
        if ocsp_client is not None:
            ocsp_client.check_chain(self.cert_chain, now)
        try:
            from signxml import XMLVerifier
        except ImportError as e:
            raise AttestationError("RIM signature verification needs the 'signxml' package (pip install attestrag[nvidia])") from e
        try:
            XMLVerifier().verify(self.xml, x509_cert=leaf.public_bytes(Encoding.PEM).decode())
        except Exception as e:  # noqa: BLE001
            raise AttestationError(f"RIM signature invalid: {type(e).__name__}: {e}") from e
        return leaf


def merge_golden(driver: ReferenceManifest | None, vbios: ReferenceManifest | None) -> dict[int, tuple[str, RimEntry]]:
    golden: dict[int, tuple[str, RimEntry]] = {}
    for source, rm in (("driver", driver), ("vbios", vbios)):
        if rm is None:
            continue
        for idx, e in rm.active().items():
            if idx in golden:
                raise AttestationError(f"driver and VBIOS manifests both claim measurement index {idx}")
            golden[idx] = (source, e)
    return golden


def match_measurements(blocks: Sequence[bytes], golden: dict[int, tuple[str, RimEntry]], nvdec_disabled: bool = False) -> list[int]:
    """Positional block k against manifest index k. Returns the matched indexes; raises on any mismatch."""
    bad = []
    for idx, (source, e) in sorted(golden.items()):
        if idx == NVDEC_INDEX and nvdec_disabled:
            continue
        if idx >= len(blocks):
            raise AttestationError(f"report has no measurement block {idx} ({source} manifest expects one)")
        v = blocks[idx]
        if len(v) != e.size or v not in e.alternatives:
            bad.append(f"{idx} ({source})")
    if bad:
        raise AttestationError("GPU measurements differ from the reference manifest at index " + ", ".join(bad))
    return [i for i in sorted(golden) if not (i == NVDEC_INDEX and nvdec_disabled)]


class RimClient:
    """Fetches manifests by id from NVIDIA's RIM service; caches them (and 404s) on disk."""

    def __init__(self, cache_dir: str | Path | None = None, base_url: str = RIM_BASE,
                 timeout: float = 30.0, offline: bool = False, missing_ttl_s: float = 86400.0):
        self.cache_dir = Path(cache_dir or Path.home() / ".cache" / "attestrag" / "nvidia" / "rim")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.base_url, self.timeout, self.offline, self.missing_ttl_s = base_url, timeout, offline, missing_ttl_s

    def fetch(self, rim_id: str) -> bytes | None:
        """The manifest XML, or None when NVIDIA has not published one under this id."""
        if not rim_id or "/" in rim_id or rim_id.startswith("."):
            raise AttestationError(f"bad RIM id {rim_id!r}")
        hit, miss = self.cache_dir / f"{rim_id}.swidtag", self.cache_dir / f"{rim_id}.missing"
        if hit.exists():
            return hit.read_bytes()
        if miss.exists() and (self.offline or time.time() - miss.stat().st_mtime < self.missing_ttl_s):
            return None
        if self.offline:
            raise AttestationError(f"RIM {rim_id} not cached and client is offline")
        req = urllib.request.Request(self.base_url + rim_id, headers={"User-Agent": "attestrag"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - fixed https base
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                miss.touch()
                return None
            raise AttestationError(f"RIM service returned {e.code} for {rim_id}") from e
        except (OSError, ValueError) as e:
            raise AttestationError(f"RIM service unreachable for {rim_id}: {e}") from e
        try:
            xml = base64.b64decode(data["rim"])
        except (KeyError, ValueError, TypeError) as e:
            raise AttestationError(f"RIM service response for {rim_id} has no manifest") from e
        tmp = hit.with_suffix(".tmp")
        tmp.write_bytes(xml)
        os.replace(tmp, hit)
        return xml


# --- revocation -----------------------------------------------------------------------------

class OcspClient:
    """OCSP against NVIDIA's responder; verified responses are cached until their nextUpdate."""

    def __init__(self, url: str = OCSP_URL, cache_dir: str | Path | None = None, timeout: float = 20.0,
                 offline: bool = False, skew_s: float = 600.0):
        self.url, self.timeout, self.offline, self.skew_s = url, timeout, offline, skew_s
        self.cache_dir = Path(cache_dir or Path.home() / ".cache" / "attestrag" / "nvidia" / "ocsp")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def check_chain(self, chain: Sequence[x509.Certificate], now: float, skip_leaf: bool = False) -> list[str]:
        """Every certificate but the root (and, for device chains, the GPU-generated leaf) must be GOOD."""
        out = []
        for i in range(1 if skip_leaf else 0, len(chain) - 1):
            self.check(chain[i], chain[i + 1], now)
            out.append(chain[i].subject.rfc4514_string())
        return out

    def check(self, cert: x509.Certificate, issuer: x509.Certificate, now: float) -> ocsp.OCSPResponse:
        key = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
        cached = self.cache_dir / f"{key}.ocsp"
        if cached.exists():
            try:
                resp = ocsp.load_der_ocsp_response(cached.read_bytes())
                self._verify(resp, cert, issuer, now, nonce=None)
                return resp
            except AttestationError:
                cached.unlink(missing_ok=True)
        if self.offline:
            raise AttestationError(f"no cached OCSP response for {cert.subject.rfc4514_string()} and client is offline")
        nonce = os.urandom(16)
        req = (ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, cert.signature_hash_algorithm)
               .add_extension(x509.OCSPNonce(nonce), critical=True).build())
        raw = self._post(req.public_bytes(Encoding.DER))
        try:
            resp = ocsp.load_der_ocsp_response(raw)
        except ValueError as e:
            raise AttestationError(f"OCSP responder returned garbage: {e}") from e
        self._verify(resp, cert, issuer, now, nonce)
        cached.write_bytes(raw)
        return resp

    def _post(self, der: bytes) -> bytes:
        req = urllib.request.Request(self.url, data=der, headers={"Content-Type": "application/ocsp-request", "User-Agent": "attestrag"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - fixed https base
                return r.read()
        except (urllib.error.URLError, OSError) as e:
            raise AttestationError(f"OCSP responder unreachable: {e}") from e

    def _verify(self, resp: ocsp.OCSPResponse, cert: x509.Certificate, issuer: x509.Certificate, now: float, nonce: bytes | None) -> None:
        name = cert.subject.rfc4514_string()
        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise AttestationError(f"OCSP for {name}: responder status {resp.response_status.name}")
        # the signer is the issuer itself or a delegated responder the issuer certified for OCSP signing
        signers = [issuer]
        for c in resp.certificates:
            try:
                _check_signed_by(c, issuer, "OCSP responder certificate")
                eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except (AttestationError, x509.ExtensionNotFound):
                continue
            if ExtendedKeyUsageOID.OCSP_SIGNING in eku and c.not_valid_before_utc.timestamp() <= now <= c.not_valid_after_utc.timestamp():
                signers.insert(0, c)
        for s in signers:
            try:
                s.public_key().verify(resp.signature, resp.tbs_response_bytes, ec.ECDSA(resp.signature_hash_algorithm))
                break
            except Exception:  # noqa: BLE001
                continue
        else:
            raise AttestationError(f"OCSP for {name}: response not signed by the issuer or a delegated responder")
        if resp.serial_number != cert.serial_number:
            raise AttestationError(f"OCSP for {name}: response is about another certificate")
        if nonce is not None:
            try:
                got = resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
            except x509.ExtensionNotFound as e:
                raise AttestationError(f"OCSP for {name}: response has no nonce") from e
            if got != nonce:
                raise AttestationError(f"OCSP for {name}: nonce mismatch")
        this = resp.this_update_utc.timestamp()
        nxt = resp.next_update_utc.timestamp() if resp.next_update_utc is not None else this + 86400.0
        if not (this - self.skew_s <= now <= nxt + self.skew_s):
            raise AttestationError(f"OCSP for {name}: response outside its validity window")
        if resp.certificate_status != ocsp.OCSPCertStatus.GOOD:
            why = resp.revocation_reason.name if resp.revocation_reason is not None else "unspecified"
            raise AttestationError(f"OCSP for {name}: certificate {resp.certificate_status.name.lower()} ({why})")
