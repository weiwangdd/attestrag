"""NodeTransport over HTTP (client side)."""

from __future__ import annotations

from ..attest.types import CompositeEvidence
from ..common.crypto import WrappedKey
from ..transport import evidence_from_dict, post_json, wrapped_to_dict


class HttpNodeTransport:
    def __init__(self, base_url: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def attestation(self, nonce: bytes) -> tuple[CompositeEvidence, bytes]:
        d = post_json(f"{self.base_url}/attestation", {"nonce": nonce.hex()}, self.timeout)
        return evidence_from_dict(d["evidence"]), bytes.fromhex(d["node_pub"])

    @staticmethod
    def _tenant_fields(tenant: str | None, auth: bytes | None) -> dict:
        d = {}
        if tenant is not None:
            d["tenant"] = tenant
        if auth is not None:
            d["auth"] = auth.hex()
        return d

    def ingest(self, doc_id: str, wrapped: WrappedKey, content_type: str = "text/plain",
               tenant: str | None = None, auth: bytes | None = None) -> int:
        d = post_json(f"{self.base_url}/ingest",
                      {"doc_id": doc_id, "wrapped": wrapped_to_dict(wrapped), "content_type": content_type,
                       **self._tenant_fields(tenant, auth)}, self.timeout)
        return int(d["chunks"])

    def query(self, wrapped_question: WrappedKey, k: int = 4,
              tenant: str | None = None, auth: bytes | None = None) -> bytes:
        d = post_json(f"{self.base_url}/query", {"wrapped": wrapped_to_dict(wrapped_question), "k": k,
                                                 **self._tenant_fields(tenant, auth)}, self.timeout)
        return bytes.fromhex(d["sealed"])
