"""Vector stores. Whatever the backend, persistent state on untrusted storage is
always AEAD-sealed with the index key the KBS released to this CVM.

- EncryptedVectorIndex: in-memory numpy/FAISS flat index; persisted as one sealed
  blob (AES-256-GCM over vectors || payloads; AAD binds format, dim and version), so a
  host that swaps, truncates or edits the file makes open() fail.
- index.qdrant.QdrantStore: a Qdrant server inside the CVM with its storage on
  tmpfs (encrypted guest RAM); persisted as a sealed collection snapshot.

Rollback: AEAD alone cannot tell an old, validly sealed file from the current one. Every
sealed file carries a version (clear header, authenticated through the AAD); the KBS keeps
the latest committed version per key and hands it to the node with the key, and open()
refuses anything older (`IndexRollback`). A file that is newer than the KBS record (the
commit after a save did not reach the KBS) is accepted and re-committed by the node.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Protocol

import numpy as np

from ..common.crypto import open_sealed, seal

try:  # optional accelerated backend
    import faiss  # type: ignore
except ImportError:  # pragma: no cover
    faiss = None

FORMAT = b"attestrag-index-v1"
VERSIONED = b"ARSV"   # header magic of a versioned sealed file: magic || be64(version) || sealed blob


class IndexRollback(RuntimeError):
    """The sealed state on disk is older than the version the KBS has on record (or missing)."""

    def __init__(self, found: int, expected: int, path: str | Path):
        if found:
            what = f"version {found}"
        elif Path(path).exists():
            what = "a sealed state without a version (sealed before versioning)"
        else:
            what = "no sealed state"
        super().__init__(f"index rollback detected: {what} at {path}, KBS has committed version {expected}; "
                         "the host restored an older snapshot or removed it, or another node committed under this key id "
                         "(an operator can reset the version at the KBS)")
        self.found, self.expected = found, expected


def seal_versioned(key: bytes, plaintext: bytes, aad: bytes, version: int) -> bytes:
    return VERSIONED + version.to_bytes(8, "big") + seal(key, plaintext, aad + b"|v=" + str(version).encode())


def open_versioned(key: bytes, blob: bytes, aad: bytes) -> tuple[bytes, int]:
    """(plaintext, version); files sealed before versioning (no header) open as version 0."""
    if blob[:4] == VERSIONED:
        version = int.from_bytes(blob[4:12], "big")
        return open_sealed(key, blob[12:], aad + b"|v=" + str(version).encode()), version
    return open_sealed(key, blob, aad), 0


def check_version(path: str | Path, found: int, min_version: int) -> None:
    if found < min_version:
        raise IndexRollback(found, min_version, path)


class VectorStore(Protocol):
    """What the node needs from a vector backend."""

    dim: int
    filename: str  # name of the sealed state file inside the node's data dir

    def __len__(self) -> int: ...
    def add(self, vectors: np.ndarray, payloads: list[dict]) -> None: ...
    def search(self, query: np.ndarray, k: int = 4) -> list[tuple[float, dict]]: ...
    def save(self, path: str | Path, key: bytes, version: int = 0) -> None:
        """Seal the current state to `path` with `key` as `version`."""
    def open(self, path: str | Path, key: bytes, min_version: int = 0) -> int:
        """Restore state from `path` if it exists (raises on tamper / wrong key / version < min_version),
        else start empty (raises if min_version > 0: the state the KBS knows of is gone). Returns the
        version found, 0 when there was no file."""


class EncryptedVectorIndex:
    filename = "index.enc"

    def __init__(self, dim: int, use_faiss: bool | None = None, filename: str | None = None):
        self.dim = dim
        if filename:
            self.filename = filename
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

    def save(self, path: str | Path, key: bytes, version: int = 0) -> None:
        buf = io.BytesIO()
        np.save(buf, self._vecs, allow_pickle=False)
        vec_bytes = buf.getvalue()
        meta = json.dumps(self._payloads).encode()
        plain = len(vec_bytes).to_bytes(8, "big") + vec_bytes + meta
        tmp = Path(str(path) + ".tmp")
        tmp.write_bytes(seal_versioned(key, plain, self._aad(), version))
        tmp.replace(path)

    def open(self, path: str | Path, key: bytes, min_version: int = 0) -> int:
        path = Path(path)
        if not path.exists():
            check_version(path, 0, min_version)
            return 0
        plain, version = open_versioned(key, path.read_bytes(), self._aad())
        check_version(path, version, min_version)
        n = int.from_bytes(plain[:8], "big")
        self._vecs = np.load(io.BytesIO(plain[8 : 8 + n]), allow_pickle=False).astype(np.float32)
        self._payloads = json.loads(plain[8 + n :])
        self._rebuild()
        return version

    @classmethod
    def load(cls, path: str | Path, key: bytes, dim: int, use_faiss: bool | None = None, min_version: int = 0):
        idx = cls(dim, use_faiss)
        idx.open(path, key, min_version)
        return idx
