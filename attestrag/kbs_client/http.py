"""KBS over HTTP: client side (inside the TEE) and routes for the server side."""

from __future__ import annotations

from ..attest.base import AttestationError
from ..attest.types import CompositeEvidence
from ..common.crypto import WrappedKey
from ..transport import (HttpError, evidence_from_dict, evidence_to_dict, post_json,
                         wrapped_from_dict, wrapped_to_dict)
from .reference_kbs import KeyReleaseDenied, ReferenceKBS


class HttpKBS:
    """Implements KBSTransport against a remote KBS."""

    def __init__(self, base_url: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def challenge(self) -> bytes:
        return bytes.fromhex(post_json(f"{self.base_url}/challenge", {}, self.timeout)["nonce"])

    def request_key(self, key_id: str, nonce: bytes, tee_pubkey: bytes,
                    evidence: CompositeEvidence) -> WrappedKey:
        try:
            d = post_json(f"{self.base_url}/key", {
                "key_id": key_id, "nonce": nonce.hex(), "tee_pubkey": tee_pubkey.hex(),
                "evidence": evidence_to_dict(evidence),
            }, self.timeout)
        except HttpError as e:
            if e.status == 403:
                raise KeyReleaseDenied(e.reasons or (e.error,)) from None
            raise
        return wrapped_from_dict(d)


def kbs_routes(kbs: ReferenceKBS) -> dict:
    def challenge(_: dict) -> dict:
        return {"nonce": kbs.challenge().hex()}

    def key(req: dict) -> dict:
        try:
            w = kbs.request_key(req["key_id"], bytes.fromhex(req["nonce"]),
                                bytes.fromhex(req["tee_pubkey"]), evidence_from_dict(req["evidence"]))
        except KeyReleaseDenied as e:
            raise HttpError(403, "key release denied", e.reasons) from None
        except AttestationError as e:
            raise HttpError(403, "key release denied", (f"attestation: {e}",)) from None
        return wrapped_to_dict(w)

    return {"/challenge": challenge, "/key": key}
