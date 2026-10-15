"""Document parsing and chunking (plain text / Markdown for now)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Chunk:
    id: str
    doc_id: str
    text: str
    meta: dict = field(default_factory=dict)


def parse(data: bytes, content_type: str = "text/plain") -> str:
    if content_type not in ("text/plain", "text/markdown"):
        raise ValueError(f"unsupported content type {content_type}")  # PDF/HTML: later
    return data.decode("utf-8")


def chunk_text(doc_id: str, text: str, max_chars: int = 800, overlap: int = 100) -> list[Chunk]:
    """Paragraph-aware chunking with a character budget and small overlap."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    buf = ""
    for p in paras:
        if buf and len(buf) + len(p) + 2 > max_chars:
            chunks.append(buf)
            buf = buf[-overlap:] + "\n\n" + p if overlap else p
        else:
            buf = f"{buf}\n\n{p}" if buf else p
        while len(buf) > max_chars:
            chunks.append(buf[:max_chars])
            buf = buf[max_chars - overlap:]
    if buf:
        chunks.append(buf)
    out = []
    for i, c in enumerate(chunks):
        cid = hashlib.sha256(f"{doc_id}:{i}:{c}".encode()).hexdigest()[:16]
        out.append(Chunk(cid, doc_id, c, {"seq": i}))
    return out
