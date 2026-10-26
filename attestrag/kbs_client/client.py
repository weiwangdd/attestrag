"""TEE-side KBS client: prove, then receive a key wrapped to an in-TEE key."""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..attest.base import CompositeAttester
from ..attest.types import CompositeEvidence
from ..common.crypto import WrappedKey, unwrap, x25519_public_bytes


class KBSTransport(Protocol):
    def challenge(self) -> bytes: ...

    def request_key(
        self, key_id: str, nonce: bytes, tee_pubkey: bytes, evidence: CompositeEvidence
    ) -> WrappedKey: ...


class KBSClient:
    def __init__(self, kbs: KBSTransport, attester: CompositeAttester):
        self.kbs = kbs
        self.attester = attester

    def get_key(self, key_id: str) -> bytes:
        eph = X25519PrivateKey.generate()  # lives only in TEE memory
        pub = x25519_public_bytes(eph.public_key())
        nonce = self.kbs.challenge()
        evidence = self.attester.attest_for(nonce, pub)
        wrapped = self.kbs.request_key(key_id, nonce, pub, evidence)
        return unwrap(eph, wrapped, info=key_id.encode())
