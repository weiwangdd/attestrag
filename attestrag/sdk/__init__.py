"""Client SDK: verify the node's evidence *before* sending it any data."""

from __future__ import annotations

import json
import os
import time
from typing import Protocol

from ..attest.base import CompositeVerifier
from ..attest.types import CompositeClaims, CompositeEvidence
from ..common.crypto import WrappedKey, new_key, open_sealed, wrap_to
from ..node import ANSWER_INFO, INGEST_INFO, QUERY_INFO
from ..policy import Policy, evaluate


class NodeUntrusted(Exception):
    pass


class NodeTransport(Protocol):
    def attestation(self, nonce: bytes) -> tuple[CompositeEvidence, bytes]: ...
    def ingest(self, doc_id: str, wrapped: WrappedKey, content_type: str = ...) -> int: ...
    def query(self, wrapped_question: WrappedKey, k: int = ...) -> bytes: ...


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
            claims = self.verifier.verify_for(evidence, nonce, node_pub)
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
        reply_key = new_key()  # one-time; only the node that can open the question learns it
        wq = wrap_to(self._pub(), json.dumps({"question": question, "reply_key": reply_key.hex()}).encode(),
                     info=QUERY_INFO)
        sealed = self.node.query(wq, k)
        return json.loads(open_sealed(reply_key, sealed, aad=ANSWER_INFO))
