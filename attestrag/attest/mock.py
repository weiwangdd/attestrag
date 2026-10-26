"""Software-only attester/verifier for local development and tests.

A MockVendor plays the role of AMD/Intel/NVIDIA: it owns an Ed25519 root key that
signs reports. Nothing here provides any security; it exists so the full
verify -> release key -> ingest -> retrieve -> generate path is testable anywhere.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .base import AttestationError, Attester, Verifier
from .types import Claims, Evidence, Platform


def _raw_pub(k: Ed25519PublicKey) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class MockVendor:
    def __init__(self, name: str = "mock-vendor", seed: bytes | None = None):
        self.name = name
        # seed: deterministic key so that separate processes (node, KBS, client) can agree on one vendor.
        # Only for the insecure baseline below; a seeded vendor is public knowledge, hence no security.
        self._key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attestrag-mock-vendor" + seed).digest()) if seed else Ed25519PrivateKey.generate()

    @property
    def root_public(self) -> bytes:
        return _raw_pub(self._key.public_key())

    def sign(self, msg: bytes) -> bytes:
        return self._key.sign(msg)


@dataclass
class MockTEEConfig:
    platform: Platform = Platform.MOCK_CPU
    measurement: str = "00" * 48
    tcb: dict[str, int] = field(
        default_factory=lambda: {"bootloader": 3, "tee": 0, "snp": 8, "microcode": 115}
    )
    debug: bool = False


class MockAttester(Attester):
    def __init__(self, vendor: MockVendor, config: MockTEEConfig | None = None):
        self.vendor = vendor
        self.config = config or MockTEEConfig()

    def identity(self) -> bytes | None:
        if not self.config.platform.is_gpu:
            return None
        from .base import gpu_identity
        return gpu_identity(Evidence(self.config.platform, b"", b"", (self.vendor.root_public,)))

    def attest(self, report_data: bytes) -> Evidence:
        body = json.dumps(
            {
                "platform": self.config.platform.value,
                "measurement": self.config.measurement,
                "tcb": self.config.tcb,
                "report_data": report_data.hex(),
                "debug": self.config.debug,
                "issued_at": time.time(),
                "signer": self.vendor.name,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return Evidence(self.config.platform, body, self.vendor.sign(body), (self.vendor.root_public,))


class MockVerifier(Verifier):
    """Trusts a fixed set of MockVendor root keys (the analogue of pinned AMD ARK / Intel roots)."""

    def __init__(self, trusted_roots: dict[str, bytes]):
        self.trusted_roots = trusted_roots  # vendor name -> raw Ed25519 pub

    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        try:
            body = json.loads(evidence.report)
        except ValueError as e:
            raise AttestationError("malformed report") from e
        root = self.trusted_roots.get(body.get("signer", ""))
        if root is None:
            raise AttestationError(f"untrusted signer {body.get('signer')!r}")
        try:
            Ed25519PublicKey.from_public_bytes(root).verify(evidence.signature, evidence.report)
        except InvalidSignature as e:
            raise AttestationError("bad report signature") from e
        if body["platform"] != evidence.platform.value:
            raise AttestationError("platform mismatch between envelope and signed report")
        rd = bytes.fromhex(body["report_data"])
        if not hmac.compare_digest(rd, expected_report_data):
            raise AttestationError("report_data does not match expected nonce/key binding")
        return Claims(
            platform=Platform(body["platform"]),
            measurement=body["measurement"],
            tcb={k: int(v) for k, v in body["tcb"].items()},
            report_data=rd,
            debug=bool(body["debug"]),
            issued_at=float(body["issued_at"]),
            signer=body["signer"],
        )


INSECURE_BASELINE_MEASUREMENT = hashlib.sha384(b"attestrag-insecure-baseline: no TEE, no attestation").hexdigest()


def insecure_baseline_vendor() -> MockVendor:
    """The one public mock vendor behind `--attester mock-insecure` / `--insecure-mock`.

    Used to run the identical pipeline in an ordinary VM as the unprotected baseline of the
    evaluation. Its key is derived from a fixed string, so anyone can mint "evidence": a KBS
    or client that trusts it protects nothing, and both print that at start.
    """
    return MockVendor("insecure-baseline", seed=b"attestrag-insecure-baseline-v1")


def insecure_baseline_attester() -> MockAttester:
    return MockAttester(insecure_baseline_vendor(), MockTEEConfig(measurement=INSECURE_BASELINE_MEASUREMENT, tcb={}))


def insecure_baseline_verifier() -> MockVerifier:
    v = insecure_baseline_vendor()
    return MockVerifier({v.name: v.root_public})
