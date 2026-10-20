"""Embedders. All run inside the TEE; nothing leaves the CVM."""

from __future__ import annotations

import hashlib
import re
from typing import Protocol

import numpy as np


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> np.ndarray:
        """Return float32 array of shape (n, dim), L2-normalized."""


class HashingEmbedder:
    """Deterministic feature-hashing bag-of-words (+ char trigrams for CJK).

    No model download; good enough for tests and tiny demos. Swap for a local
    sentence-transformer / GGUF embedding model in real deployments.
    """

    _tok = re.compile(r"[a-z0-9]+|[一-鿿]")

    def __init__(self, dim: int = 512):
        self.dim = dim

    def _features(self, text: str) -> list[str]:
        toks = self._tok.findall(text.lower())
        feats = list(toks)
        feats += [a + b for a, b in zip(toks, toks[1:])]
        return feats

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            for f in self._features(t):
                h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "big")
                out[i, h % self.dim] += 1.0 if (h >> 63) else -1.0
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return out / norms


class OpenAIEmbedder:
    """Embeddings from an OpenAI-compatible /v1/embeddings endpoint (e.g. llama-server
    --embedding inside the same CVM). Vectors are L2-normalized here regardless of the
    server's pooling/normalization settings. `dim` is probed once at construction."""

    def __init__(self, base_url: str = "http://127.0.0.1:8090/v1", model: str = "local",
                 api_key: str | None = None, timeout: float = 120.0, batch: int = 32):
        import urllib.request  # noqa: F401  (documented dependency: stdlib only)
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.batch = batch
        self.dim = int(self._call(["dimension probe"]).shape[1])

    def _call(self, texts: list[str]) -> np.ndarray:
        import json
        import urllib.request

        body = json.dumps({"model": self.model, "input": texts}).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.base_url}/embeddings", body, headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.load(r)
        rows = sorted(data["data"], key=lambda d: d.get("index", 0))
        if len(rows) != len(texts):
            raise RuntimeError(f"embedding server returned {len(rows)} vectors for {len(texts)} inputs")
        return np.asarray([d["embedding"] for d in rows], dtype=np.float32)

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        out = np.vstack([self._call(texts[i:i + self.batch]) for i in range(0, len(texts), self.batch)])
        if out.shape[1] != self.dim:
            raise RuntimeError(f"embedding dim changed: {out.shape[1]} != {self.dim}")
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return out / norms
