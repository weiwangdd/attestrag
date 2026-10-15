"""The TEE-resident AttestRAG node: everything in here runs inside the CVM.

Boot:   prove to KBS -> receive index DEK -> open encrypted index.
Serve:  attestation(nonce) for clients; ingest/query over payloads encrypted to
        the node's transport key, whose public half is bound into every report.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .attest.base import CompositeAttester
from .attest.binding import cpu_report_data
from .attest.types import CompositeEvidence
from .common.crypto import WrappedKey, unwrap, wrap_to, x25519_public_bytes
from .embed import Embedder
from .generate import Generator
from .index import EncryptedVectorIndex
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
        self.index: EncryptedVectorIndex | None = None

    @property
    def index_path(self) -> Path:
        return self.data_dir / "index.enc"

    def start(self) -> None:
        self._dek = self.kbs.get_key(self.index_key_id)  # raises KeyReleaseDenied
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.index_path.exists():
            self.index = EncryptedVectorIndex.load(self.index_path, self._dek, self.embedder.dim)
        else:
            self.index = EncryptedVectorIndex(self.embedder.dim)

    def _require_started(self) -> EncryptedVectorIndex:
        if self.index is None or self._dek is None:
            raise RuntimeError("node not started (key not released)")
        return self.index

    # --- client-facing API -------------------------------------------------
    def attestation(self, nonce: bytes) -> tuple[CompositeEvidence, bytes]:
        return self.attester.attest(cpu_report_data(nonce, self.transport_pub)), self.transport_pub

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

    def query(self, wrapped_question: WrappedKey, reply_pub: bytes, k: int = 4) -> WrappedKey:
        index = self._require_started()
        question = unwrap(self._transport, wrapped_question, info=QUERY_INFO).decode()
        hits = Retriever(self.embedder, index).retrieve(question, k)
        answer = self.generator.generate(question, hits)
        payload = json.dumps({"answer": asdict(answer), "hits": [asdict(h) for h in hits]}).encode()
        return wrap_to(reply_pub, payload, info=ANSWER_INFO)
