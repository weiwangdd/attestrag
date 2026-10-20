"""QdrantStore against a real Qdrant process (skipped unless QDRANT_BIN or `qdrant` on PATH)."""

import os
import shutil
import socket
import subprocess
import time
import urllib.request

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag

from attestrag.common.crypto import new_key
from attestrag.embed import HashingEmbedder
from attestrag.index.qdrant import QdrantStore

QDRANT_BIN = os.environ.get("QDRANT_BIN") or shutil.which("qdrant")
pytestmark = pytest.mark.skipif(not QDRANT_BIN, reason="qdrant binary not available (set QDRANT_BIN)")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Qdrant:
    def __init__(self, storage):
        self.storage = storage
        self.port = _free_port()
        self.proc = None

    def start(self):
        env = {**os.environ, "QDRANT__SERVICE__HTTP_PORT": str(self.port),
               "QDRANT__SERVICE__GRPC_PORT": str(_free_port()), "QDRANT__SERVICE__HOST": "127.0.0.1",
               "QDRANT__STORAGE__STORAGE_PATH": str(self.storage / "storage"),
               "QDRANT__STORAGE__SNAPSHOTS_PATH": str(self.storage / "snapshots"),
               "QDRANT__TELEMETRY_DISABLED": "true", "QDRANT__LOG_LEVEL": "WARN"}
        self.proc = subprocess.Popen([QDRANT_BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{self.url}/healthz", timeout=1).read()
                return self
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("qdrant did not start")

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(10)
            self.proc = None


@pytest.fixture
def qdrant(tmp_path):
    q = Qdrant(tmp_path / "q1").start()
    yield q
    q.stop()


def test_store_roundtrip_seal_restore_tamper(tmp_path, qdrant):
    emb = HashingEmbedder(64)
    texts = ["the cat sat", "rust memory safety", "confidential computing with SEV-SNP"]
    key, path = new_key(), tmp_path / "snap.enc"
    store = QdrantStore(qdrant.url, "t", dim=64)
    store.open(path, key)                      # no sealed state yet: creates the collection
    assert len(store) == 0
    store.add(emb.embed(texts), [{"chunk_id": f"c{i}", "doc_id": "d", "text": t} for i, t in enumerate(texts)])
    assert len(store) == 3
    top = store.search(emb.embed(["SEV-SNP confidential"])[0], 1)
    assert top[0][1]["text"].startswith("confidential") and 0 < top[0][0] <= 1.0001
    store.add(emb.embed([texts[0]]), [{"chunk_id": "c0", "doc_id": "d", "text": texts[0]}])  # same id -> upsert
    assert len(store) == 3

    store.save(path, key)
    raw = path.read_bytes()
    assert b"confidential" not in raw and b"SEV" not in raw

    # a fresh Qdrant with empty storage (like a rebooted CVM): restore from the sealed snapshot
    qdrant.stop()
    q2 = Qdrant(tmp_path / "q2").start()
    try:
        s2 = QdrantStore(q2.url, "t", dim=64)
        s2.open(path, key)
        assert len(s2) == 3
        assert s2.search(emb.embed(["rust safety"])[0], 1)[0][1]["chunk_id"] == "c1"

        with pytest.raises(InvalidTag):
            QdrantStore(q2.url, "t", dim=64).open(path, new_key())
        with pytest.raises(InvalidTag):           # AAD binds the collection name
            QdrantStore(q2.url, "other", dim=64).open(path, key)
        bad = bytearray(raw); bad[-1] ^= 1; (tmp_path / "bad.enc").write_bytes(bytes(bad))
        with pytest.raises(InvalidTag):
            QdrantStore(q2.url, "t", dim=64).open(tmp_path / "bad.enc", key)
    finally:
        q2.stop()


def test_dim_mismatch_detected(tmp_path, qdrant):
    QdrantStore(qdrant.url, "d", dim=16).open(tmp_path / "none.enc", new_key())
    with pytest.raises(Exception, match="dim"):
        QdrantStore(qdrant.url, "d", dim=32).open(tmp_path / "none.enc", new_key())


def test_node_with_qdrant_store_persists_across_restart(tmp_path, qdrant, verifier, policy, make_attester):
    from attestrag.generate import StubGenerator
    from attestrag.kbs_client import KBSClient, ReferenceKBS
    from attestrag.node import AttestRAGNode
    from attestrag.sdk import AttestRAGClient

    kbs = ReferenceKBS(verifier, policy)
    kbs.put_key("index-dek", new_key())

    def node():
        att = make_attester()
        store = QdrantStore(qdrant.url, "node", dim=256)
        return AttestRAGNode(att, KBSClient(kbs, att), HashingEmbedder(256), StubGenerator(),
                             tmp_path / "data", store=store)

    n1 = node(); n1.start()
    c1 = AttestRAGClient(n1, verifier, policy); c1.connect()
    c1.upload("snp", b"The VCEK signs SEV-SNP attestation reports.")
    c1.upload("cook", b"Toast the rice before adding stock.")
    assert n1.index_path.name == "qdrant-node.snapshot.enc" and n1.index_path.exists()

    # simulate reboot: Qdrant storage (tmpfs) is gone, only the sealed snapshot on the data disk remains
    qdrant.stop(); shutil.rmtree(tmp_path / "q1"); qdrant.start()
    n2 = node(); n2.start()
    assert len(n2.index) == 2
    c2 = AttestRAGClient(n2, verifier, policy); c2.connect()
    assert c2.ask("Which key signs SNP reports?", k=1)["hits"][0]["doc_id"] == "snp"
