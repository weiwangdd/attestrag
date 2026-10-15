"""Vector index whose persisted form is always AEAD-encrypted.

Plaintext vectors and chunk text exist only in (hardware-encrypted) CVM memory.
On disk: nonce || AES-256-GCM(vectors || payloads), AAD binds format+dim, so a
host that swaps, truncates or edits the file causes load() to fail.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import numpy as np

from ..common.crypto import open_sealed, seal

try:  # optional accelerated backend
    import faiss  # type: ignore
except ImportError:  # pragma: no cover
    faiss = None

FORMAT = b"attestrag-index-v1"


class EncryptedVectorIndex:
    def __init__(self, dim: int, use_faiss: bool | None = None):
        self.dim = dim
        self.use_faiss = (faiss is not None) if use_faiss is None else use_faiss
        self._vecs = np.zeros((0, dim), dtype=np.float32)
        self._payloads: list[dict] = []
        self._faiss = None
        self._rebuild()

    def __len__(self) -> int:
        return len(self._payloads)

    def _rebuild(self) -> None:
        if self.use_faiss:
            self._faiss = faiss.IndexFlatIP(self.dim)  # HNSW/IVF once corpora grow
            if len(self._vecs):
                self._faiss.add(self._vecs)

    def add(self, vectors: np.ndarray, payloads: list[dict]) -> None:
        vectors = np.ascontiguousarray(vectors, dtype=np.float32)
        if vectors.shape != (len(payloads), self.dim):
            raise ValueError("vectors/payloads shape mismatch")
        self._vecs = np.vstack([self._vecs, vectors])
        self._payloads.extend(payloads)
        if self._faiss is not None:
            self._faiss.add(vectors)

    def search(self, query: np.ndarray, k: int = 4) -> list[tuple[float, dict]]:
        if not len(self):
            return []
        q = np.ascontiguousarray(query.reshape(1, -1), dtype=np.float32)
        k = min(k, len(self))
        if self._faiss is not None:
            scores, idx = self._faiss.search(q, k)
            pairs = zip(scores[0].tolist(), idx[0].tolist())
        else:
            s = (self._vecs @ q[0])
            top = np.argsort(-s)[:k]
            pairs = ((float(s[i]), int(i)) for i in top)
        return [(score, self._payloads[i]) for score, i in pairs if i >= 0]

    def _aad(self) -> bytes:
        return FORMAT + b"|dim=" + str(self.dim).encode()

    def save(self, path: str | Path, key: bytes) -> None:
        buf = io.BytesIO()
        np.save(buf, self._vecs, allow_pickle=False)
        vec_bytes = buf.getvalue()
        meta = json.dumps(self._payloads).encode()
        plain = len(vec_bytes).to_bytes(8, "big") + vec_bytes + meta
        tmp = Path(str(path) + ".tmp")
        tmp.write_bytes(seal(key, plain, self._aad()))
        tmp.replace(path)

    @classmethod
    def load(cls, path: str | Path, key: bytes, dim: int, use_faiss: bool | None = None):
        idx = cls(dim, use_faiss)
        plain = open_sealed(key, Path(path).read_bytes(), idx._aad())
        n = int.from_bytes(plain[:8], "big")
        idx._vecs = np.load(io.BytesIO(plain[8 : 8 + n]), allow_pickle=False).astype(np.float32)
        idx._payloads = json.loads(plain[8 + n :])
        idx._rebuild()
        return idx
