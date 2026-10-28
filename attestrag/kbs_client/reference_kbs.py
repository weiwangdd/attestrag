"""In-process reference Key Broker Service.

Implements the release protocol that a real deployment would run in the
customer's own trust domain (or on Trustee KBS):

  1. client -> challenge()                      : single-use nonce
  2. client -> request_key(id, nonce, pk, ev)   : evidence with
        report_data = cpu_report_data(nonce, pk, gpu identities)
  3. KBS verifies evidence, evaluates policy, and only then returns the key
     wrapped to `pk` (whose private half never leaves the TEE), together with the
     key's committed index version and the tenant's client token, and SIGNS the
     release with its identity key: the node pins that public key (it is part of
     the measured image), so the host in the middle cannot hand it a key of its
     own choosing or an older version.
  4. node -> commit_version(id, v, tag)         : after each ingest the node seals
     the index as version v and commits v; the tag is an HMAC under a key derived
     from the DEK, so only a party that was released the key can advance it, and
     the KBS only ever moves forward.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..attest.base import AttestationError, CompositeVerifier
from ..attest.types import CompositeEvidence
from ..common.crypto import KEY_LEN, WrappedKey, mac, mac_ok, subkey, wrap_to
from ..policy.engine import Decision, Policy, evaluate

RELEASE_LABEL = b"attestrag-release-v1"   # signed: label, key id, nonce, TEE pk, wrapped blob
COMMIT_LABEL = b"attestrag-commit-v1"     # HKDF label of the commit MAC key derived from the DEK


class KeyReleaseDenied(Exception):
    def __init__(self, reasons: tuple[str, ...]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


class VersionCommitRejected(Exception):
    def __init__(self, reasons: tuple[str, ...]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


@dataclass
class KeyRecord:
    """One key id = one tenant index: its DEK, the last committed index version, the tenant's client token."""
    key: bytes
    version: int = 0
    token: bytes | None = None


@dataclass(frozen=True)
class KeyRelease:
    wrapped: WrappedKey   # plaintext = be64(version) || key || token (token may be empty)
    signature: bytes      # Ed25519 by the KBS identity over release_message(...)


@dataclass(frozen=True)
class AuditRecord:
    at: float
    key_id: str
    allowed: bool
    reasons: tuple[str, ...]
    measurement: str | None


def pack_secret(record: KeyRecord) -> bytes:
    return record.version.to_bytes(8, "big") + record.key + (record.token or b"")


def unpack_secret(plain: bytes) -> tuple[int, bytes, bytes | None]:
    """(version, key, token)"""
    if len(plain) not in (8 + KEY_LEN, 8 + 2 * KEY_LEN):
        raise ValueError(f"released secret has {len(plain)} bytes")
    version, key, token = int.from_bytes(plain[:8], "big"), plain[8:8 + KEY_LEN], plain[8 + KEY_LEN:]
    return version, key, token or None


def release_message(key_id: str, nonce: bytes, tee_pubkey: bytes, wrapped: WrappedKey) -> bytes:
    out = b""
    for p in (RELEASE_LABEL, key_id.encode(), nonce, tee_pubkey, wrapped.eph_pub, wrapped.ciphertext):
        out += len(p).to_bytes(8, "big") + p
    return out


def verify_release(kbs_pubkey: bytes, key_id: str, nonce: bytes, tee_pubkey: bytes, rel: KeyRelease) -> None:
    """Raises AttestationError when the release was not signed by the pinned KBS for this session."""
    try:
        Ed25519PublicKey.from_public_bytes(kbs_pubkey).verify(rel.signature, release_message(key_id, nonce, tee_pubkey, rel.wrapped))
    except (InvalidSignature, ValueError) as e:
        raise AttestationError(f"KBS release signature invalid: {type(e).__name__}") from None


def commit_tag(dek: bytes, key_id: str, version: int) -> bytes:
    return mac(subkey(dek, COMMIT_LABEL), key_id.encode(), version.to_bytes(8, "big"))


def identity_public_bytes(identity: Ed25519PrivateKey) -> bytes:
    return identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class ReferenceKBS:
    def __init__(
        self,
        verifier: CompositeVerifier,
        policy: Policy,
        nonce_ttl_s: float = 60.0,
        clock=time.time,
        identity: Ed25519PrivateKey | None = None,
        on_change: Callable[[dict[str, KeyRecord]], None] | None = None,
    ):
        self.verifier = verifier
        self.policy = policy
        self.nonce_ttl_s = nonce_ttl_s
        self.clock = clock
        self.identity = identity or Ed25519PrivateKey.generate()
        self.on_change = on_change   # called with the records after every version commit (persistence)
        self._keys: dict[str, KeyRecord] = {}
        self._nonces: dict[bytes, float] = {}
        self.audit: list[AuditRecord] = []
        self.commits: list[tuple[float, str, int]] = []

    @property
    def public_key(self) -> bytes:
        return identity_public_bytes(self.identity)

    def put_key(self, key_id: str, key: bytes, version: int = 0, token: bytes | None = None) -> None:
        self._keys[key_id] = KeyRecord(key, version, token)

    def record(self, key_id: str) -> KeyRecord:
        return self._keys[key_id]

    def version(self, key_id: str) -> int:
        return self._keys[key_id].version

    def challenge(self) -> bytes:
        n = os.urandom(32)
        self._nonces[n] = self.clock() + self.nonce_ttl_s
        return n

    def _deny(self, key_id: str, reasons: tuple[str, ...], measurement: str | None = None):
        self.audit.append(AuditRecord(self.clock(), key_id, False, reasons, measurement))
        raise KeyReleaseDenied(reasons)

    def request_key(
        self, key_id: str, nonce: bytes, tee_pubkey: bytes, evidence: CompositeEvidence
    ) -> KeyRelease:
        expiry = self._nonces.pop(nonce, None)  # single use, even on failure
        if expiry is None or self.clock() > expiry:
            self._deny(key_id, ("unknown or expired nonce",))
        if key_id not in self._keys:
            self._deny(key_id, (f"unknown key id {key_id!r}",))
        try:
            claims = self.verifier.verify_for(evidence, nonce, tee_pubkey)
        except AttestationError as e:
            self._deny(key_id, (f"attestation: {e}",))
        decision: Decision = evaluate(self.policy, claims, self.clock())
        if not decision.allow:
            self._deny(key_id, decision.reasons, claims.cpu.measurement)
        self.audit.append(AuditRecord(self.clock(), key_id, True, (), claims.cpu.measurement))
        wrapped = wrap_to(tee_pubkey, pack_secret(self._keys[key_id]), info=key_id.encode())
        return KeyRelease(wrapped, self.identity.sign(release_message(key_id, nonce, tee_pubkey, wrapped)))

    def commit_version(self, key_id: str, version: int, tag: bytes) -> int:
        """Advance the committed index version; only forward, only with a tag under the key's commit MAC key."""
        rec = self._keys.get(key_id)
        if rec is None:
            raise VersionCommitRejected((f"unknown key id {key_id!r}",))
        if not mac_ok(subkey(rec.key, COMMIT_LABEL), tag, key_id.encode(), version.to_bytes(8, "big")):
            raise VersionCommitRejected(("commit tag invalid",))
        if version <= rec.version:
            raise VersionCommitRejected((f"version {version} is not newer than the committed {rec.version}",))
        rec.version = version
        self.commits.append((self.clock(), key_id, version))
        if self.on_change:
            self.on_change(self._keys)
        return version
