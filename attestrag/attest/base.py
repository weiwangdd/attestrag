"""Attester / Verifier interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..common.crypto import sha384
from .binding import cpu_report_data, gpu_report_data
from .types import Claims, CompositeClaims, CompositeEvidence, Evidence, Platform


class AttestationError(Exception):
    """Evidence failed cryptographic verification (as opposed to failing policy)."""


def gpu_identity(ev: Evidence) -> bytes:
    """The GPU identity a verifier derives from GPU evidence; must equal what the attester put into
    the CPU report (Attester.identity). NVIDIA: SHA-384 over the attestation-key certificate (the
    leaf of the chain the GPU returns); mock GPU: SHA-384 over its vendor root."""
    if not ev.cert_chain:
        raise AttestationError("GPU evidence carries no certificate")
    if ev.platform == Platform.NVIDIA_CC:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        try:
            leaf = x509.load_pem_x509_certificates(ev.cert_chain[0].split(b"\0", 1)[0])[0]
        except ValueError as e:
            raise AttestationError(f"GPU certificate chain unreadable: {e}") from e
        return sha384(b"nvidia-ak-cert", leaf.public_bytes(Encoding.DER))
    return sha384(ev.platform.value.encode(), ev.cert_chain[0])


class Attester(ABC):
    """Runs *inside* the TEE and produces evidence over caller-chosen report_data."""

    @abstractmethod
    def attest(self, report_data: bytes) -> Evidence: ...

    def identity(self) -> bytes | None:
        """GPU attesters: the identity committed into the CPU report (see gpu_identity). CPU: None."""
        return None


class Verifier(ABC):
    """Runs outside (KBS, client SDK). Checks signatures and freshness binding."""

    @abstractmethod
    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        """Return claims, or raise AttestationError."""


class CompositeAttester:
    """Produces CPU evidence plus GPU evidences bound to it."""

    def __init__(self, cpu: Attester, gpus: list[Attester] | None = None):
        self.cpu = cpu
        self.gpus = gpus or []

    def attest(self, report_data: bytes) -> CompositeEvidence:
        """Evidence over a caller-chosen CPU report_data (no GPU identities inside it)."""
        cpu_ev = self.cpu.attest(report_data)
        g_rd = gpu_report_data(report_data)
        return CompositeEvidence(cpu_ev, tuple(g.attest(g_rd) for g in self.gpus))

    def attest_for(self, nonce: bytes, tee_pubkey: bytes) -> CompositeEvidence:
        """Session evidence: the CPU report commits to nonce, pk and the identities of the attached GPUs."""
        ids = [i for i in (g.identity() for g in self.gpus) if i is not None]
        return self.attest(cpu_report_data(nonce, tee_pubkey, ids))


class CompositeVerifier:
    """Dispatches to per-platform verifiers and enforces the CPU<->GPU binding."""

    def __init__(self, verifiers: dict):
        self.verifiers = verifiers  # Platform -> Verifier

    def _get(self, ev: Evidence) -> Verifier:
        try:
            return self.verifiers[ev.platform]
        except KeyError:
            raise AttestationError(f"no verifier for platform {ev.platform.value}") from None

    def verify_for(self, ev: CompositeEvidence, nonce: bytes, tee_pubkey: bytes) -> CompositeClaims:
        """Session verification: recompute the CPU report_data from nonce, pk and the identities carried
        by the GPU evidence itself, then verify. A GPU half substituted in transit changes the identity,
        and the CPU report no longer matches."""
        ids = [gpu_identity(g) for g in ev.gpus]
        return self.verify(ev, cpu_report_data(nonce, tee_pubkey, ids))

    def verify(self, ev: CompositeEvidence, expected_report_data: bytes) -> CompositeClaims:
        if ev.cpu.platform.is_gpu:
            raise AttestationError("primary evidence must come from a CPU TEE")
        cpu = self._get(ev.cpu).verify(ev.cpu, expected_report_data)
        g_rd = gpu_report_data(cpu.report_data)
        gpus = []
        for g in ev.gpus:
            if not g.platform.is_gpu:
                raise AttestationError("non-GPU evidence in GPU slot")
            gpus.append(self._get(g).verify(g, g_rd))
        return CompositeClaims(cpu, tuple(gpus))
