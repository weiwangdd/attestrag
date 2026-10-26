"""The TEE-resident AttestRAG node: everything in here runs inside the CVM.

Boot:   prove to KBS -> receive index DEK -> open encrypted index.
Serve:  attestation(nonce) for clients; ingest/query over payloads encrypted to
        the node's transport key, whose public half is bound into every report.
        The answer is sealed with a one-time key the client sent inside the
        encrypted question, so only the node that could decrypt the question
        (i.e. the attested one) can produce an answer the client accepts.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .attest.base import CompositeAttester
from .attest.types import CompositeEvidence
from .common.crypto import WrappedKey, seal, unwrap, x25519_public_bytes
from .embed import Embedder
from .generate import Generator
from .index import EncryptedVectorIndex, VectorStore
from .ingest import chunk_text, parse
from .kbs_client import KBSClient
from .retrieve import Retriever

INGEST_INFO = b"attestrag-ingest-v1|"
QUERY_INFO = b"attestrag-query-v1"
ANSWER_INFO = b"attestrag-answer-v1"


class AttestRAGNode:
    def __init__(
        self,
        attester: CompositeAttester,
        kbs: KBSClient,
        embedder: Embedder,
        generator: Generator,
        data_dir: str | Path,
        index_key_id: str = "index-dek",
        store: VectorStore | None = None,
    ):
        self.attester = attester
        self.kbs = kbs
        self.embedder = embedder
        self.generator = generator
        self.data_dir = Path(data_dir)
        self.index_key_id = index_key_id
        self._transport = X25519PrivateKey.generate()
        self.transport_pub = x25519_public_bytes(self._transport.public_key())
        self._dek: bytes | None = None
        self._store = store
        self.index: VectorStore | None = None

    @property
    def index_path(self) -> Path:
        return self.data_dir / (self._store.filename if self._store is not None else EncryptedVectorIndex.filename)

    def start(self) -> None:
        self._dek = self.kbs.get_key(self.index_key_id)  # raises KeyReleaseDenied
        self.data_dir.mkdir(parents=True, exist_ok=True)
        store = self._store if self._store is not None else EncryptedVectorIndex(self.embedder.dim)  # no `or`: it would call __len__
        if store.dim != self.embedder.dim:
            raise RuntimeError(f"vector store dim {store.dim} != embedder dim {self.embedder.dim}")
        store.open(self.index_path, self._dek)  # restores sealed state if present
        self.index = store

    def _require_started(self) -> VectorStore:
        if self.index is None or self._dek is None:
            raise RuntimeError("node not started (key not released)")
        return self.index

    # --- client-facing API -------------------------------------------------
    def attestation(self, nonce: bytes) -> tuple[CompositeEvidence, bytes]:
        return self.attester.attest_for(nonce, self.transport_pub), self.transport_pub

    def ingest(self, doc_id: str, wrapped: WrappedKey, content_type: str = "text/plain") -> int:
        index = self._require_started()
        data = unwrap(self._transport, wrapped, info=INGEST_INFO + doc_id.encode())
        chunks = chunk_text(doc_id, parse(data, content_type))
        if not chunks:
            return 0
        vecs = self.embedder.embed([c.text for c in chunks])
        index.add(vecs, [{"chunk_id": c.id, "doc_id": c.doc_id, "text": c.text, **c.meta} for c in chunks])
        index.save(self.index_path, self._dek)
        return len(chunks)

    def query(self, wrapped_question: WrappedKey, k: int = 4) -> bytes:
        """wrapped_question = wrap_to(node_pub, {"question", "reply_key"}); returns seal(reply_key, answer)."""
        index = self._require_started()
        req = json.loads(unwrap(self._transport, wrapped_question, info=QUERY_INFO))
        question, reply_key = req["question"], bytes.fromhex(req["reply_key"])
        hits = Retriever(self.embedder, index).retrieve(question, k)
        answer = self.generator.generate(question, hits)
        payload = json.dumps({"answer": asdict(answer), "hits": [asdict(h) for h in hits]}).encode()
        return seal(reply_key, payload, aad=ANSWER_INFO)


def node_routes(node: AttestRAGNode) -> dict:
    """HTTP routes for AttestRAGNode (see transport.JsonServer)."""
    from .transport import evidence_to_dict, wrapped_from_dict

    def attestation(req: dict) -> dict:
        ev, pub = node.attestation(bytes.fromhex(req["nonce"]))
        return {"evidence": evidence_to_dict(ev), "node_pub": pub.hex()}

    def ingest(req: dict) -> dict:
        n = node.ingest(req["doc_id"], wrapped_from_dict(req["wrapped"]), req.get("content_type", "text/plain"))
        return {"chunks": n}

    def query(req: dict) -> dict:
        return {"sealed": node.query(wrapped_from_dict(req["wrapped"]), int(req.get("k", 4))).hex()}

    return {"/attestation": attestation, "/ingest": ingest, "/query": query}
