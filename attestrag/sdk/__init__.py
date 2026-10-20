"""Client SDK: verify the node's evidence *before* sending it any data."""

from __future__ import annotations

import json
import os
import time
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..attest.base import CompositeVerifier
from ..attest.binding import cpu_report_data
from ..attest.types import CompositeClaims, CompositeEvidence
from ..common.crypto import WrappedKey, unwrap, wrap_to, x25519_public_bytes
from ..node import ANSWER_INFO, INGEST_INFO, QUERY_INFO
from ..policy import Policy, evaluate


class NodeUntrusted(Exception):
    pass


class NodeTransport(Protocol):
    def attestation(self, nonce: bytes) -> tuple[CompositeEvidence, bytes]: ...
    def ingest(self, doc_id: str, wrapped: WrappedKey, content_type: str = ...) -> int: ...
    def query(self, wrapped_question: WrappedKey, reply_pub: bytes, k: int = ...) -> WrappedKey: ...


class AttestRAGClient:
    def __init__(self, node: NodeTransport, verifier: CompositeVerifier, policy: Policy):
        self.node = node
        self.verifier = verifier
        self.policy = policy
        self._node_pub: bytes | None = None
        self.claims: CompositeClaims | None = None

    def connect(self) -> CompositeClaims:
        nonce = os.urandom(32)
        evidence, node_pub = self.node.attestation(nonce)
        try:
            claims = self.verifier.verify(evidence, cpu_report_data(nonce, node_pub))
        except Exception as e:
            raise NodeUntrusted(f"attestation failed: {e}") from e
        decision = evaluate(self.policy, claims, time.time())
        if not decision.allow:
            raise NodeUntrusted("; ".join(decision.reasons))
        self._node_pub, self.claims = node_pub, claims
        return claims

    def _pub(self) -> bytes:
        if self._node_pub is None:
            raise NodeUntrusted("call connect() first; refusing to send data to an unverified node")
        return self._node_pub

    def upload(self, doc_id: str, data: bytes, content_type: str = "text/plain") -> int:
        wrapped = wrap_to(self._pub(), data, info=INGEST_INFO + doc_id.encode())
        return self.node.ingest(doc_id, wrapped, content_type)

    def ask(self, question: str, k: int = 4) -> dict:
        reply = X25519PrivateKey.generate()
        wq = wrap_to(self._pub(), question.encode(), info=QUERY_INFO)
        wa = self.node.query(wq, x25519_public_bytes(reply.public_key()), k)
        return json.loads(unwrap(reply, wa, info=ANSWER_INFO))
