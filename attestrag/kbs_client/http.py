"""KBS over HTTP: client side (inside the TEE) and routes for the server side."""

from __future__ import annotations

from ..attest.base import AttestationError
from ..attest.types import CompositeEvidence
from ..transport import (HttpError, evidence_from_dict, evidence_to_dict, post_json,
                         wrapped_from_dict, wrapped_to_dict)
from .reference_kbs import KeyRelease, KeyReleaseDenied, ReferenceKBS, VersionCommitRejected


class HttpKBS:
    """Implements KBSTransport against a remote KBS."""

    def __init__(self, base_url: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def challenge(self) -> bytes:
        return bytes.fromhex(post_json(f"{self.base_url}/challenge", {}, self.timeout)["nonce"])

    def request_key(self, key_id: str, nonce: bytes, tee_pubkey: bytes,
                    evidence: CompositeEvidence) -> KeyRelease:
        try:
            d = post_json(f"{self.base_url}/key", {
                "key_id": key_id, "nonce": nonce.hex(), "tee_pubkey": tee_pubkey.hex(),
                "evidence": evidence_to_dict(evidence),
            }, self.timeout)
        except HttpError as e:
            if e.status == 403:
                raise KeyReleaseDenied(e.reasons or (e.error,)) from None
            raise
        return KeyRelease(wrapped_from_dict(d), bytes.fromhex(d.get("signature", "")))

    def commit_version(self, key_id: str, version: int, tag: bytes) -> int:
        try:
            d = post_json(f"{self.base_url}/commit", {"key_id": key_id, "version": version, "tag": tag.hex()}, self.timeout)
        except HttpError as e:
            if e.status in (403, 409):
                raise VersionCommitRejected(e.reasons or (e.error,)) from None
            raise
        return int(d["version"])


def kbs_routes(kbs: ReferenceKBS) -> dict:
    def challenge(_: dict) -> dict:
        return {"nonce": kbs.challenge().hex()}

    def key(req: dict) -> dict:
        try:
            rel = kbs.request_key(req["key_id"], bytes.fromhex(req["nonce"]),
                                  bytes.fromhex(req["tee_pubkey"]), evidence_from_dict(req["evidence"]))
        except KeyReleaseDenied as e:
            raise HttpError(403, "key release denied", e.reasons) from None
        except AttestationError as e:
            raise HttpError(403, "key release denied", (f"attestation: {e}",)) from None
        return {**wrapped_to_dict(rel.wrapped), "signature": rel.signature.hex()}

    def commit(req: dict) -> dict:
        try:
            v = kbs.commit_version(req["key_id"], int(req["version"]), bytes.fromhex(req["tag"]))
        except VersionCommitRejected as e:
            status = 403 if "tag" in e.reasons[0] else 409
            raise HttpError(status, "version commit rejected", e.reasons) from None
        return {"version": v}

    return {"/challenge": challenge, "/key": key, "/commit": commit}
