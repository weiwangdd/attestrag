"""NVIDIA confidential-computing GPU attestation (Hopper H100/H200, Blackwell).

Attester (runs in the CVM that owns the GPU): NVML returns, for a caller-chosen
32-byte nonce, the SPDM GET_MEASUREMENTS transcript, i.e. the 37-byte request the
driver sent followed by the GPU's signed MEASUREMENTS response; a second call
returns the attestation-key (AK) certificate chain of the GPU.

Verifier (KBS and client SDK): parse the transcript, chain the AK certificate to
the pinned NVIDIA Device Identity CA, check the ECDSA-P384/SHA-384 signature over
request || response-without-signature, check the nonce, check that the firmware ID
in the AK certificate equals the one the report carries, and reduce the DMTF
measurement blocks to one composite digest that a policy can pin.

Binding to the CPU session: the composite attester hands every GPU attester
gpu_report_data(cpu_rd) (48 bytes); the SPDM request carries a 32-byte nonce, so
the first 32 bytes are used on both sides. Note that the MEASUREMENTS response has
its own nonce, chosen by the GPU (SPDM 1.1 section 10.11): freshness comes from the
requester nonce, which the signature covers as part of the request half of the
transcript, not from the response nonce.

Optional, through nvidia_rim: NVIDIA's reference manifests (the published golden values
for the driver and VBIOS measurement blocks) and OCSP revocation of the certificate chains.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding

from .base import AttestationError, Attester, Verifier
from .nvidia_rim import (NVDEC_DISABLED, OcspClient, ReferenceManifest, RimClient, driver_rim_id, match_measurements,
                         merge_golden, vbios_rim_id, verify_chain)
from .types import Claims, Evidence, Platform

NONCE_LEN = 32
REQUEST_LEN = 37          # SPDM 1.1 GET_MEASUREMENTS: ver, code, p1, p2, nonce[32], slot
SIGNATURE_LEN = 96        # ECDSA P-384, raw r || s
SPDM_MEASUREMENTS_CODE = 0x60
DMTF_SPEC = 1
FWID_OIDS = ("2.23.133.5.4.1", "2.23.133.5.4.1.1")  # TCG DICE TcbInfo / FWID
OPAQUE_FIELDS = {1: "cert_issuer_name", 2: "cert_authority_key_id", 3: "driver_version", 4: "gpu_info",
                 5: "sku", 6: "vbios_version", 7: "manufacturer_id", 8: "tamper_detection", 9: "smc",
                 10: "vpr", 11: "nvdec0_status", 12: "measurement_count", 13: "cpr_info", 14: "board_id",
                 15: "chip_sku", 16: "chip_sku_mod", 17: "project", 18: "project_sku", 19: "project_sku_mod",
                 20: "fwid", 21: "protected_pcie_status", 22: "switch_pdi", 23: "floorswept_ports",
                 24: "position_id", 25: "lock_switch_status", 32: "gpu_link_conn", 33: "sys_enable_status"}
ROOTS_DIR = Path(__file__).parent / "nvidia_roots"   # device_*.pem: device identity roots; corim_*.pem: RIM signing roots


def load_roots(pattern: str) -> dict[bytes, x509.Certificate]:
    certs = [c for f in sorted(ROOTS_DIR.glob(pattern)) for c in x509.load_pem_x509_certificates(f.read_bytes())]
    return {c.public_bytes(Encoding.DER): c for c in certs}


@dataclass(frozen=True)
class GpuReport:
    request: bytes
    response: bytes
    nonce: bytes                                  # requester nonce (the binding), from the GET_MEASUREMENTS request
    measurements: tuple[tuple[int, bytes], ...]  # (index, DMTF measurement value)
    opaque: dict[str, bytes] = field(default_factory=dict)
    signature: bytes = b""
    responder_nonce: bytes = b""                  # GPU-chosen nonce in the MEASUREMENTS response

    @property
    def signed_data(self) -> bytes:
        return self.request + self.response[:-SIGNATURE_LEN]

    @property
    def composite_measurement(self) -> bytes:
        """SHA-384 over (index || value) of every block in index order: one pinnable digest."""
        h = hashlib.sha384()
        for idx, val in sorted(self.measurements):
            h.update(bytes([idx]))
            h.update(val)
        return h.digest()

    def opaque_str(self, name: str) -> str:
        v = self.opaque.get(name)
        return v.split(b"\0", 1)[0].decode("ascii", "replace") if v else ""

    @property
    def vbios_version(self) -> str:
        """VBIOS as nvidia-smi prints it ("96.00.b7.00.02"); the GPU sends 5 binary bytes."""
        v = self.opaque.get("vbios_version", b"")
        if len(v) >= 5 and not all(32 <= b < 127 for b in v.rstrip(b"\0")):
            return f"{v[3]:02x}.{v[2]:02x}.{v[1]:02x}.{v[0]:02x}.{v[4]:02x}"
        return self.opaque_str("vbios_version").lower()

    @classmethod
    def parse(cls, blob: bytes) -> "GpuReport":
        if len(blob) <= REQUEST_LEN + SIGNATURE_LEN:
            raise AttestationError(f"GPU report too short ({len(blob)} bytes)")
        req, resp = blob[:REQUEST_LEN], blob[REQUEST_LEN:]
        req_nonce = req[4:4 + NONCE_LEN]
        if resp[1] != SPDM_MEASUREMENTS_CODE:
            raise AttestationError(f"not an SPDM MEASUREMENTS response (code {resp[1]:#x})")
        n_blocks = resp[4]
        rec_len = int.from_bytes(resp[5:8], "little")
        pos = 8
        record = resp[pos:pos + rec_len]
        if len(record) != rec_len:
            raise AttestationError("truncated measurement record")
        pos += rec_len
        responder_nonce = resp[pos:pos + NONCE_LEN]
        pos += NONCE_LEN
        opaque_len = int.from_bytes(resp[pos:pos + 2], "little")
        pos += 2
        opaque_raw = resp[pos:pos + opaque_len]
        pos += opaque_len
        sig = resp[pos:pos + SIGNATURE_LEN]
        if len(responder_nonce) != NONCE_LEN or len(opaque_raw) != opaque_len or len(sig) != SIGNATURE_LEN or pos + SIGNATURE_LEN != len(resp):
            raise AttestationError("malformed SPDM MEASUREMENTS response")
        measurements = []
        i = 0
        for _ in range(n_blocks):
            if i + 4 > len(record):
                raise AttestationError("truncated measurement block")
            idx, spec, size = record[i], record[i + 1], int.from_bytes(record[i + 2:i + 4], "little")
            if spec != DMTF_SPEC:
                raise AttestationError(f"measurement block {idx} is not DMTF-specified")
            m = record[i + 4:i + 4 + size]
            if len(m) != size or size < 3:
                raise AttestationError(f"truncated measurement block {idx}")
            vsize = int.from_bytes(m[1:3], "little")
            value = m[3:3 + vsize]
            if len(value) != vsize:
                raise AttestationError(f"truncated DMTF measurement {idx}")
            measurements.append((idx, value))
            i += 4 + size
        if i != len(record):
            raise AttestationError("measurement record has trailing bytes")
        opaque: dict[str, bytes] = {}
        j = 0
        while j + 4 <= len(opaque_raw):
            ftype, fsize = struct.unpack_from("<HH", opaque_raw, j)
            j += 4
            opaque[OPAQUE_FIELDS.get(ftype, f"field_{ftype}")] = opaque_raw[j:j + fsize]
            j += fsize
        return cls(req, resp, req_nonce, tuple(measurements), opaque, sig, responder_nonce)


def load_pem_chain(pem: bytes) -> list[x509.Certificate]:
    certs = x509.load_pem_x509_certificates(pem)
    if not certs:
        raise AttestationError("empty GPU certificate chain")
    return certs


def cert_fwid(cert: x509.Certificate) -> bytes | None:
    for ext in cert.extensions:
        if ext.oid.dotted_string in FWID_OIDS:
            raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
            return raw[-48:] if len(raw) >= 48 else raw
    return None


class NvidiaVerifier(Verifier):
    """Verifies an NVIDIA GPU attestation transcript against pinned NVIDIA roots."""

    def __init__(self, roots: list[x509.Certificate] | None = None, clock=time.time,
                 rim: RimClient | None = None, ocsp: OcspClient | None = None,
                 rim_roots: list[x509.Certificate] | None = None):
        self.clock = clock
        self.roots = {r.public_bytes(Encoding.DER): r for r in roots} if roots is not None else load_roots("device_*.pem")
        self.rim_roots = {r.public_bytes(Encoding.DER): r for r in rim_roots} if rim_roots is not None else load_roots("corim_*.pem")
        self.rim, self.ocsp = rim, ocsp
        self._rim_cache: dict[str, ReferenceManifest | None] = {}

    def _verify_chain(self, chain: list[x509.Certificate], now: float) -> x509.Certificate:
        try:
            return verify_chain(chain, self.roots, now)
        except AttestationError as e:
            raise AttestationError(f"GPU {e}") from e

    def _manifest(self, rim_id: str, now: float) -> ReferenceManifest | None:
        """Fetched, chain-checked (plus OCSP if enabled) and signature-checked; None if NVIDIA has none."""
        if rim_id not in self._rim_cache:
            xml = self.rim.fetch(rim_id)
            rm = None
            if xml is not None:
                rm = ReferenceManifest.parse(xml)
                try:
                    rm.verify(self.rim_roots, now, self.ocsp)
                except AttestationError as e:
                    raise AttestationError(f"RIM {rim_id}: {e}") from e
            self._rim_cache[rim_id] = rm
        return self._rim_cache[rim_id]

    def _check_rims(self, rep: GpuReport, now: float) -> dict[str, str]:
        driver_id = driver_rim_id(rep.opaque_str("driver_version"))
        vbios_id = vbios_rim_id(rep.opaque_str("project"), rep.opaque_str("project_sku"), rep.opaque_str("chip_sku"), rep.vbios_version)
        out, manifests = {}, {}
        for key, rim_id, version in (("rim_driver", driver_id, rep.opaque_str("driver_version").lower()),
                                      ("rim_vbios", vbios_id, rep.vbios_version)):
            rm = self._manifest(rim_id, now)
            if rm is not None and rm.version != version:
                raise AttestationError(f"RIM {rim_id} is for version {rm.version}, report says {version}")
            manifests[key] = rm
            out[key] = ("ok:" if rm is not None else "not-found:") + rim_id
        nvdec = rep.opaque.get("nvdec0_status", b"")
        matched = match_measurements([v for _, v in rep.measurements], merge_golden(manifests["rim_driver"], manifests["rim_vbios"]),
                                     nvdec_disabled=bool(nvdec) and nvdec[0] == NVDEC_DISABLED)
        out["rim_matched"] = ",".join(str(i) for i in matched)
        return out

    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        if evidence.platform != Platform.NVIDIA_CC:
            raise AttestationError("not NVIDIA CC evidence")
        if not evidence.cert_chain:
            raise AttestationError("GPU evidence carries no certificate chain")
        rep = GpuReport.parse(evidence.report)
        now = self.clock()
        leaf = self._verify_chain(load_pem_chain(evidence.cert_chain[0]), now)
        r, s = int.from_bytes(rep.signature[:48], "big"), int.from_bytes(rep.signature[48:], "big")
        pub = leaf.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
            raise AttestationError("GPU attestation key is not ECDSA P-384")
        try:
            pub.verify(encode_dss_signature(r, s), rep.signed_data, ec.ECDSA(hashes.SHA384()))
        except Exception as e:  # noqa: BLE001
            raise AttestationError("bad GPU report signature") from e
        if rep.nonce != expected_report_data[:NONCE_LEN]:
            raise AttestationError("GPU request nonce does not match the expected binding")
        fwid = rep.opaque.get("fwid")
        if fwid:
            cf = cert_fwid(leaf)
            if cf is None or cf != fwid:
                raise AttestationError("firmware ID in the AK certificate does not match the report")
        extra = {
            "driver_version": rep.opaque_str("driver_version"),
            "project": rep.opaque_str("project"),
            "project_sku": rep.opaque_str("project_sku"),
            "chip_sku": rep.opaque_str("chip_sku"),
            "vbios_version": rep.vbios_version,
            "fwid": (fwid or b"").hex(),
            "measurement_count": str(len(rep.measurements)),
            "ak_subject": leaf.subject.rfc4514_string(),
        }
        for idx, val in rep.measurements:
            extra[f"msr_{idx}"] = val.hex()
        chain = load_pem_chain(evidence.cert_chain[0])
        if self.ocsp is not None:
            self.ocsp.check_chain(chain, now, skip_leaf=True)   # the AK leaf is minted by the GPU, not by a CA
            extra["ocsp"] = "good"
        if self.rim is not None:
            extra.update(self._check_rims(rep, now))
        return Claims(
            platform=Platform.NVIDIA_CC,
            measurement=rep.composite_measurement.hex(),
            tcb={},
            report_data=expected_report_data,
            debug=False,
            issued_at=now,
            signer="nvidia-device-identity-ca",
            extra=extra,
        )


def probe_cc_gpus() -> list[int]:
    """Indices of GPUs that answer the attestation-certificate query, i.e. are in CC mode ([] without a driver)."""
    try:
        import pynvml
        pynvml.nvmlInit()
    except Exception as e:  # noqa: BLE001 - no driver / no GPU is a normal CPU-only boot
        print(f"[attest] no GPU attestation ({e})", file=sys.stderr)
        return []
    try:
        out = []
        for i in range(pynvml.nvmlDeviceGetCount()):
            try:
                pynvml.nvmlDeviceGetConfComputeGpuCertificate(pynvml.nvmlDeviceGetHandleByIndex(i))
                out.append(i)
            except Exception as e:  # noqa: BLE001
                print(f"[attest] GPU {i}: no CC attestation ({e})", file=sys.stderr)
        return out
    finally:
        try:
            pynvml.nvmlShutdown()
        except Exception:  # noqa: BLE001
            pass


def gpu_indices(spec: list[str]) -> list[int]:
    """--gpu INDEX|auto (repeatable) -> sorted unique indices; 'auto' = every CC-mode GPU found."""
    out: set[int] = set()
    for g in spec:
        out.update(probe_cc_gpus() if g == "auto" else [int(g)])
    return sorted(out)


class NvidiaAttester(Attester):
    """Fetches the GPU's attestation transcript and AK certificate chain through NVML."""

    def __init__(self, index: int = 0):
        self.index = index

    @staticmethod
    def _chain(pynvml, h) -> bytes:
        cert = pynvml.nvmlDeviceGetConfComputeGpuCertificate(h)
        return bytes(cert.attestationCertChain[:cert.attestationCertChainSize])

    def identity(self) -> bytes:
        """SHA-384 over the GPU's attestation-key certificate, committed into the CPU report."""
        try:
            import pynvml
            pynvml.nvmlInit()
        except Exception as e:  # noqa: BLE001
            raise AttestationError(f"NVML init failed: {e}") from e
        try:
            chain = self._chain(pynvml, pynvml.nvmlDeviceGetHandleByIndex(self.index))
        except Exception as e:  # noqa: BLE001
            raise AttestationError(f"NVML certificate query failed: {e}") from e
        finally:
            try:
                pynvml.nvmlShutdown()
            except Exception:  # noqa: BLE001
                pass
        from .base import gpu_identity
        return gpu_identity(Evidence(Platform.NVIDIA_CC, b"", b"", (chain,)))

    def attest(self, report_data: bytes) -> Evidence:
        try:
            import pynvml  # nvidia-ml-py, only needed inside the GPU CVM
        except ImportError as e:
            raise AttestationError("nvidia-ml-py (pynvml) is not installed") from e
        nonce = report_data[:NONCE_LEN]
        if len(nonce) != NONCE_LEN:
            raise AttestationError("report_data must be at least 32 bytes")
        try:
            pynvml.nvmlInit()
        except Exception as e:  # noqa: BLE001
            raise AttestationError(f"NVML init failed: {e}") from e
        try:
            h = pynvml.nvmlDeviceGetHandleByIndex(self.index)
            rep = pynvml.nvmlDeviceGetConfComputeGpuAttestationReport(h, list(nonce))
            blob = bytes(rep.attestationReport[:rep.attestationReportSize])
            chain = self._chain(pynvml, h)
        except AttestationError:
            raise
        except Exception as e:  # noqa: BLE001
            raise AttestationError(f"NVML attestation failed: {e}") from e
        finally:
            try:
                pynvml.nvmlShutdown()
            except Exception:  # noqa: BLE001
                pass
        return Evidence(Platform.NVIDIA_CC, blob, b"", (chain,))
