"""OpenAI-compatible embedder / generator against a fake in-process server."""

import numpy as np
import pytest

from attestrag.embed import OpenAIEmbedder
from attestrag.generate import OpenAICompatibleGenerator
from attestrag.retrieve import Hit
from attestrag.transport import JsonServer


@pytest.fixture
def fake_llm():
    calls = {"embeddings": [], "chat": []}

    def embeddings(req):
        calls["embeddings"].append(req)
        vecs = []
        for i, t in enumerate(req["input"]):
            v = np.zeros(8); v[len(t) % 8] = 3.0; v[0] += 1.0   # deterministic, not normalized
            vecs.append({"index": i, "embedding": v.tolist()})
        return {"data": list(reversed(vecs)), "model": "fake-embed"}  # out of order on purpose

    def chat(req):
        calls["chat"].append(req)
        user = req["messages"][-1]["content"]
        cited = [line.split("]")[0][1:] for line in user.splitlines() if line.startswith("[")]
        return {"choices": [{"message": {"content": f"Answer based on [{cited[0]}]."}}], "model": "fake-chat"}

    srv = JsonServer({"/v1/embeddings": embeddings, "/v1/chat/completions": chat}).start()
    yield srv.url + "/v1", calls
    srv.stop()


def test_openai_embedder_probes_dim_normalizes_and_batches(fake_llm):
    url, calls = fake_llm
    e = OpenAIEmbedder(url, batch=2)
    assert e.dim == 8 and len(calls["embeddings"]) == 1
    v = e.embed(["a", "bb", "ccc"])
    assert v.shape == (3, 8) and v.dtype == np.float32
    assert np.allclose(np.linalg.norm(v, axis=1), 1.0)
    assert v[0, 1] > 0 and v[1, 2] > 0 and v[2, 3] > 0   # order restored from "index"
    assert len(calls["embeddings"]) == 3   # probe + 2 batches
    assert e.embed([]).shape == (0, 8)


def test_openai_generator_cites_chunks(fake_llm):
    url, calls = fake_llm
    g = OpenAICompatibleGenerator(url, model="m")
    hits = [Hit(0.9, "c1", "d", "text one"), Hit(0.5, "c2", "d", "text two")]
    a = g.generate("q?", hits)
    assert a.text == "Answer based on [c1]." and a.citations == ("c1",) and a.model == "fake-chat"
    assert calls["chat"][0]["temperature"] == 0 and "[c2] text two" in calls["chat"][0]["messages"][-1]["content"]
