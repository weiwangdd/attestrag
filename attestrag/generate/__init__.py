"""Generators: an offline stub, and any OpenAI-compatible endpoint.

The OpenAI-compatible backend covers a local llama.cpp `llama-server` inside the
same CVM (http://127.0.0.1:8080/v1) as well as an attested remote inference API.
For a remote API the endpoint itself must be attested before use; that check is
not wired in yet (see docs/threat-model.md).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from ..retrieve import Hit

SYSTEM_PROMPT = (
    "Answer using only the provided context. Cite chunk ids in [brackets]. "
    "If the context is insufficient, say so."
)


def build_prompt(question: str, hits: list[Hit]) -> str:
    ctx = "\n\n".join(f"[{h.chunk_id}] {h.text}" for h in hits)
    return f"Context:\n{ctx}\n\nQuestion: {question}"


# The judge shares the system prompt and the whole context/question prefix with the answer prompt and only
# appends its instruction, so the inference server's prompt cache serves the second call from the first:
# the judge then costs a few tokens of prefill, not a second pass over the context.
JUDGE_SUFFIX = (
    "\n\nBefore answering: does the context above explicitly state the specific fact the question asks for? "
    "Being on the same topic is not enough; if the exact fact is missing or you are unsure, the answer is NO. "
    "Reply with exactly one word, YES or NO."
)


def build_judge_prompt(question: str, hits: list[Hit]) -> str:
    return build_prompt(question, hits) + JUDGE_SUFFIX


@dataclass(frozen=True)
class Answer:
    text: str
    citations: tuple[str, ...]
    model: str


class Generator(Protocol):
    def generate(self, question: str, hits: list[Hit]) -> Answer: ...

    def warm_up(self) -> None:
        """One throw-away completion so the first real request does not pay for CUDA/graph initialisation."""
        ...

    def judge(self, question: str, hits: list[Hit]) -> bool:
        """True when the context is judged sufficient to answer; the relevance gate's second stage."""
        ...


class StubGenerator:
    """Extractive 'generator': returns the best chunk's text. Deterministic, offline."""

    def generate(self, question: str, hits: list[Hit]) -> Answer:
        if not hits:
            return Answer("I don't know (no relevant context).", (), "stub")
        best = hits[0]
        return Answer(f"{best.text} [{best.chunk_id}]", (best.chunk_id,), "stub")

    def warm_up(self) -> None:
        pass

    def judge(self, question: str, hits: list[Hit]) -> bool:
        """Offline stand-in: sufficient when the best chunk shares a word of 5+ letters with the question."""
        words = {w.lower().strip(".,?!") for w in question.split() if len(w) >= 5}
        return bool(hits) and any(w in hits[0].text.lower() for w in words)


class OpenAICompatibleGenerator:
    def __init__(self, base_url: str = "http://127.0.0.1:8080/v1", model: str = "local",
                 api_key: str | None = None, timeout: float = 120.0, max_tokens: int = 512):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens

    def generate(self, question: str, hits: list[Hit]) -> Answer:
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(question, hits)},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0,
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", body, headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.load(r)
        text = data["choices"][0]["message"]["content"]
        cited = tuple(h.chunk_id for h in hits if f"[{h.chunk_id}]" in text)
        return Answer(text, cited, data.get("model", self.model))

    def warm_up(self) -> None:
        self._chat([{"role": "user", "content": "warm-up"}], max_tokens=1)

    def _chat(self, messages: list[dict], max_tokens: int) -> dict:
        body = json.dumps({"model": self.model, "messages": messages, "max_tokens": max_tokens, "temperature": 0}).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", body, headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r)

    def judge(self, question: str, hits: list[Hit]) -> bool:
        """One short completion at temperature 0; anything that does not start with YES is a refusal."""
        if not hits:
            return False
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_judge_prompt(question, hits)},
            ],
            "max_tokens": 3,
            "temperature": 0,
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", body, headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.load(r)
        verdict = data["choices"][0]["message"]["content"].strip().upper()
        return verdict.startswith("YES")
