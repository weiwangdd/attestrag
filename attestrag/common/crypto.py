"""Small, auditable crypto helpers shared by all components.

- AEAD sealing (AES-256-GCM) for data at rest.
- Key wrapping to an ephemeral X25519 public key (ECDH + HKDF + AES-GCM),
  used by the KBS to release a key only to the TEE that proved possession of
  the matching private key inside its attestation report.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12
KEY_LEN = 32


def sha384(*parts: bytes) -> bytes:
    """Length-prefixed SHA-384 over parts (SNP/TDX report_data is 64 bytes; 48 fit)."""
    h = hashlib.sha384()
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return h.digest()


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def mac(key: bytes, *parts: bytes) -> bytes:
    """HMAC-SHA256 over length-prefixed parts (tenant request authentication, version commits)."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return h.digest()


def mac_ok(key: bytes, tag: bytes, *parts: bytes) -> bool:
    return hmac.compare_digest(mac(key, *parts), tag)


def subkey(key: bytes, label: bytes) -> bytes:
    """A purpose-bound key derived from `key` (HKDF-SHA256, no salt); e.g. the commit MAC key from a DEK."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=label).derive(key)


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_sealed(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)


def x25519_public_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _kek(shared: bytes, eph_pub: bytes, rcpt_pub: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=eph_pub + rcpt_pub,
        info=b"attestrag-wrap-v1|" + info,
    ).derive(shared)


@dataclass(frozen=True)
class WrappedKey:
    eph_pub: bytes
    ciphertext: bytes


def wrap_to(recipient_pub: bytes, secret: bytes, info: bytes = b"") -> WrappedKey:
    eph = X25519PrivateKey.generate()
    eph_pub = x25519_public_bytes(eph.public_key())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    kek = _kek(shared, eph_pub, recipient_pub, info)
    return WrappedKey(eph_pub, seal(kek, secret, aad=info))


def unwrap(recipient: X25519PrivateKey, wrapped: WrappedKey, info: bytes = b"") -> bytes:
    rcpt_pub = x25519_public_bytes(recipient.public_key())
    shared = recipient.exchange(X25519PublicKey.from_public_bytes(wrapped.eph_pub))
    kek = _kek(shared, wrapped.eph_pub, rcpt_pub, info)
    return open_sealed(kek, wrapped.ciphertext, aad=info)
