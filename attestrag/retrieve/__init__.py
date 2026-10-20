from __future__ import annotations

from dataclasses import dataclass

from ..embed import Embedder
from ..index import EncryptedVectorIndex


@dataclass(frozen=True)
class Hit:
    score: float
    chunk_id: str
    doc_id: str
    text: str


class Retriever:
    def __init__(self, embedder: Embedder, index: EncryptedVectorIndex):
        self.embedder = embedder
        self.index = index

    def retrieve(self, query: str, k: int = 4) -> list[Hit]:
        q = self.embedder.embed([query])[0]
        return [
            Hit(score, p["chunk_id"], p["doc_id"], p["text"]) for score, p in self.index.search(q, k)
        ]
