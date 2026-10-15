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
