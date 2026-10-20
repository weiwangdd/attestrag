"""In-process reference Key Broker Service.

Implements the release protocol that a real deployment would run in the
customer's own trust domain (or on Trustee KBS):

  1. client -> challenge()                      : single-use nonce
  2. client -> request_key(id, nonce, pk, ev)   : evidence with
        report_data = cpu_report_data(nonce, pk)
  3. KBS verifies evidence, evaluates policy, and only then returns the key
     wrapped to `pk` (whose private half never leaves the TEE).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from ..attest.base import AttestationError, CompositeVerifier
from ..attest.binding import cpu_report_data
from ..attest.types import CompositeEvidence
from ..common.crypto import WrappedKey, wrap_to
from ..policy.engine import Decision, Policy, evaluate


class KeyReleaseDenied(Exception):
    def __init__(self, reasons: tuple[str, ...]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True)
class AuditRecord:
    at: float
    key_id: str
    allowed: bool
    reasons: tuple[str, ...]
    measurement: str | None


class ReferenceKBS:
    def __init__(
        self,
        verifier: CompositeVerifier,
        policy: Policy,
        nonce_ttl_s: float = 60.0,
        clock=time.time,
    ):
        self.verifier = verifier
        self.policy = policy
        self.nonce_ttl_s = nonce_ttl_s
        self.clock = clock
        self._keys: dict[str, bytes] = {}
        self._nonces: dict[bytes, float] = {}
        self.audit: list[AuditRecord] = []

    def put_key(self, key_id: str, key: bytes) -> None:
        self._keys[key_id] = key

    def challenge(self) -> bytes:
        n = os.urandom(32)
        self._nonces[n] = self.clock() + self.nonce_ttl_s
        return n

    def _deny(self, key_id: str, reasons: tuple[str, ...], measurement: str | None = None):
        self.audit.append(AuditRecord(self.clock(), key_id, False, reasons, measurement))
        raise KeyReleaseDenied(reasons)

    def request_key(
        self, key_id: str, nonce: bytes, tee_pubkey: bytes, evidence: CompositeEvidence
    ) -> WrappedKey:
        expiry = self._nonces.pop(nonce, None)  # single use, even on failure
        if expiry is None or self.clock() > expiry:
            self._deny(key_id, ("unknown or expired nonce",))
        if key_id not in self._keys:
            self._deny(key_id, (f"unknown key id {key_id!r}",))
        try:
            claims = self.verifier.verify(evidence, cpu_report_data(nonce, tee_pubkey))
        except AttestationError as e:
            self._deny(key_id, (f"attestation: {e}",))
        decision: Decision = evaluate(self.policy, claims, self.clock())
        if not decision.allow:
            self._deny(key_id, decision.reasons, claims.cpu.measurement)
        self.audit.append(AuditRecord(self.clock(), key_id, True, (), claims.cpu.measurement))
        return wrap_to(tee_pubkey, self._keys[key_id], info=key_id.encode())
