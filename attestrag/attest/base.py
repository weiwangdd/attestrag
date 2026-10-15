"""Attester / Verifier interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod

from .binding import gpu_report_data
from .types import Claims, CompositeClaims, CompositeEvidence, Evidence


class AttestationError(Exception):
    """Evidence failed cryptographic verification (as opposed to failing policy)."""


class Attester(ABC):
    """Runs *inside* the TEE and produces evidence over caller-chosen report_data."""

    @abstractmethod
    def attest(self, report_data: bytes) -> Evidence: ...


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
        cpu_ev = self.cpu.attest(report_data)
        g_rd = gpu_report_data(report_data)
        return CompositeEvidence(cpu_ev, tuple(g.attest(g_rd) for g in self.gpus))


class CompositeVerifier:
    """Dispatches to per-platform verifiers and enforces the CPU<->GPU binding."""

    def __init__(self, verifiers: dict):
        self.verifiers = verifiers  # Platform -> Verifier

    def _get(self, ev: Evidence) -> Verifier:
        try:
            return self.verifiers[ev.platform]
        except KeyError:
            raise AttestationError(f"no verifier for platform {ev.platform.value}") from None

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
