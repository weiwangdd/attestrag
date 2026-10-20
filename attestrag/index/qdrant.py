"""Qdrant as the vector backend, run inside the CVM.

Live data lives in the Qdrant process whose storage directory is on tmpfs, i.e. in
SEV-encrypted guest RAM; nothing of it touches the host-visible disk. Persistence:
`save()` asks Qdrant for a collection snapshot, seals it (AES-256-GCM with the
KBS-released index key, AAD binds collection + dim) and writes the ciphertext to the
untrusted data disk; `open()` unseals it in memory and uploads it to Qdrant's
snapshot-recover endpoint. Only the REST API and the standard library are used.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import numpy as np

from ..common.crypto import open_sealed, seal

FORMAT = b"attestrag-qdrant-snapshot-v1"
POINT_NS = uuid.UUID("1b6d2c7e-3a58-4f1a-9b6a-5f0c9d2e7a11")


class QdrantError(RuntimeError):
    pass


class QdrantStore:
    def __init__(self, base_url: str = "http://127.0.0.1:6333", collection: str = "attestrag",
                 dim: int = 1024, timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.collection = collection
        self.dim = dim
        self.timeout = timeout
        self.filename = f"qdrant-{collection}.snapshot.enc"

    # ---------------------------------------------------------------- REST
    def _req(self, method: str, path: str, body: dict | None = None, raw: bool = False,
             data: bytes | None = None, content_type: str | None = None):
        if data is None and body is not None:
            data, content_type = json.dumps(body).encode(), "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data,
                                     {"Content-Type": content_type} if data else {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read() if raw else json.load(r)
        except urllib.error.HTTPError as e:
            raise QdrantError(f"{method} {path} -> HTTP {e.code}: {e.read()[:300]!r}") from None
        except OSError as e:
            raise QdrantError(f"qdrant at {self.base_url} unreachable: {e}") from None

    def _ensure_collection(self) -> None:
        try:
            info = self._req("GET", f"/collections/{self.collection}")["result"]
            size = info["config"]["params"]["vectors"]["size"]
            if size != self.dim:
                raise QdrantError(f"collection {self.collection} has dim {size}, expected {self.dim}")
            return
        except QdrantError as e:
            if "HTTP 404" not in str(e):
                raise
        self._req("PUT", f"/collections/{self.collection}",
                  {"vectors": {"size": self.dim, "distance": "Cosine"}})

    # ---------------------------------------------------------------- VectorStore
    def __len__(self) -> int:
        return int(self._req("POST", f"/collections/{self.collection}/points/count", {"exact": True})["result"]["count"])

    def add(self, vectors: np.ndarray, payloads: list[dict]) -> None:
        vectors = np.asarray(vectors, dtype=np.float32)
        if vectors.shape != (len(payloads), self.dim):
            raise ValueError("vectors/payloads shape mismatch")
        points = [{"id": str(uuid.uuid5(POINT_NS, p["chunk_id"])), "vector": v.tolist(), "payload": p}
                  for v, p in zip(vectors, payloads)]
        for i in range(0, len(points), 256):
            self._req("PUT", f"/collections/{self.collection}/points?wait=true", {"points": points[i:i + 256]})

    def search(self, query: np.ndarray, k: int = 4) -> list[tuple[float, dict]]:
        q = np.asarray(query, dtype=np.float32).reshape(-1).tolist()
        res = self._req("POST", f"/collections/{self.collection}/points/query",
                        {"query": q, "limit": k, "with_payload": True})["result"]["points"]
        return [(float(p["score"]), p["payload"]) for p in res]

    def _aad(self) -> bytes:
        return FORMAT + b"|" + self.collection.encode() + b"|dim=" + str(self.dim).encode()

    def save(self, path: str | Path, key: bytes) -> None:
        name = self._req("POST", f"/collections/{self.collection}/snapshots?wait=true")["result"]["name"]
        try:
            snap = self._req("GET", f"/collections/{self.collection}/snapshots/{name}", raw=True)
        finally:
            try:
                self._req("DELETE", f"/collections/{self.collection}/snapshots/{name}?wait=true")
            except QdrantError:
                pass
        tmp = Path(str(path) + ".tmp")
        tmp.write_bytes(seal(key, snap, self._aad()))
        tmp.replace(path)

    def open(self, path: str | Path, key: bytes) -> None:
        path = Path(path)
        if not path.exists():
            self._ensure_collection()
            return
        snap = open_sealed(key, path.read_bytes(), self._aad())   # InvalidTag on tamper / wrong key
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"snapshot\"; "
                f"filename=\"{self.collection}.snapshot\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                ).encode() + snap + f"\r\n--{boundary}--\r\n".encode()
        self._req("POST", f"/collections/{self.collection}/snapshots/upload?wait=true&priority=snapshot",
                  data=body, content_type=f"multipart/form-data; boundary={boundary}")
        self._ensure_collection()
