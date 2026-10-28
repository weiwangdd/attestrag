"""TEE-side KBS client: prove, then receive a key wrapped to an in-TEE key."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..attest.base import CompositeAttester
from ..attest.types import CompositeEvidence
from ..common.crypto import unwrap, x25519_public_bytes
from .reference_kbs import KeyRelease, commit_tag, unpack_secret, verify_release


class KBSTransport(Protocol):
    def challenge(self) -> bytes: ...

    def request_key(
        self, key_id: str, nonce: bytes, tee_pubkey: bytes, evidence: CompositeEvidence
    ) -> KeyRelease: ...

    def commit_version(self, key_id: str, version: int, tag: bytes) -> int: ...


@dataclass(frozen=True)
class Released:
    key: bytes
    version: int          # index version the KBS has on record for this key
    token: bytes | None   # tenant client token (None: the tenant is open, no client authentication)


class KBSClient:
    def __init__(self, kbs: KBSTransport, attester: CompositeAttester, kbs_pubkey: bytes | None = None):
        """kbs_pubkey: the Ed25519 identity of the KBS to accept releases from. Without it the release
        is NOT authenticated and whoever sits between node and KBS can substitute a key (tests only)."""
        self.kbs = kbs
        self.attester = attester
        self.kbs_pubkey = kbs_pubkey

    def get_release(self, key_id: str) -> Released:
        eph = X25519PrivateKey.generate()  # lives only in TEE memory
        pub = x25519_public_bytes(eph.public_key())
        nonce = self.kbs.challenge()
        evidence = self.attester.attest_for(nonce, pub)
        rel = self.kbs.request_key(key_id, nonce, pub, evidence)
        if self.kbs_pubkey is not None:
            verify_release(self.kbs_pubkey, key_id, nonce, pub, rel)   # AttestationError
        version, key, token = unpack_secret(unwrap(eph, rel.wrapped, info=key_id.encode()))
        return Released(key, version, token)

    def get_key(self, key_id: str) -> bytes:
        return self.get_release(key_id).key

    def commit_version(self, key_id: str, version: int, key: bytes) -> int:
        return self.kbs.commit_version(key_id, version, commit_tag(key, key_id, version))
