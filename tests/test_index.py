import numpy as np
import pytest
from cryptography.exceptions import InvalidTag

from attestrag.common.crypto import new_key
from attestrag.embed import HashingEmbedder
from attestrag.index import EncryptedVectorIndex


@pytest.mark.parametrize("use_faiss", [False, True])
def test_roundtrip_and_tamper(tmp_path, use_faiss):
    pytest.importorskip("faiss") if use_faiss else None
    emb = HashingEmbedder(64)
    texts = ["the cat sat", "rust memory safety", "confidential computing with SEV-SNP"]
    idx = EncryptedVectorIndex(64, use_faiss=use_faiss)
    idx.add(emb.embed(texts), [{"chunk_id": str(i), "doc_id": "d", "text": t} for i, t in enumerate(texts)])
    key, path = new_key(), tmp_path / "i.enc"
    idx.save(path, key)

    raw = path.read_bytes()
    assert b"confidential" not in raw  # nothing in the clear

    loaded = EncryptedVectorIndex.load(path, key, 64, use_faiss=use_faiss)
    top = loaded.search(emb.embed(["SEV-SNP confidential"])[0], 1)
    assert top[0][1]["text"].startswith("confidential")

    with pytest.raises(InvalidTag):
        EncryptedVectorIndex.load(path, new_key(), 64)
    path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(InvalidTag):
        EncryptedVectorIndex.load(path, key, 64)


def test_dim_bound_in_aad(tmp_path):
    key, path = new_key(), tmp_path / "i.enc"
    EncryptedVectorIndex(64).save(path, key)
    with pytest.raises(InvalidTag):
        EncryptedVectorIndex.load(path, key, 128)


def test_versioned_sealing_and_rollback_detection(tmp_path):
    from attestrag.index import IndexRollback
    emb = HashingEmbedder(64)
    key, path = new_key(), tmp_path / "i.enc"
    idx = EncryptedVectorIndex(64)
    idx.add(emb.embed(["v1 content"]), [{"chunk_id": "a", "doc_id": "d", "text": "v1 content"}])
    idx.save(path, key, version=1)
    old = path.read_bytes()
    assert old[:4] == b"ARSV" and int.from_bytes(old[4:12], "big") == 1   # version readable in the clear, authenticated by the AAD
    idx.add(emb.embed(["v2 content"]), [{"chunk_id": "b", "doc_id": "d", "text": "v2 content"}])
    idx.save(path, key, version=2)

    assert EncryptedVectorIndex(64).open(path, key, min_version=2) == 2
    assert len(EncryptedVectorIndex.load(path, key, 64, min_version=1)) == 2   # newer than the record is fine
    path.write_bytes(old)                                                      # the host restores yesterday's file
    with pytest.raises(IndexRollback, match="version 1 .* committed version 2"):
        EncryptedVectorIndex(64).open(path, key, min_version=2)
    assert EncryptedVectorIndex(64).open(path, key, min_version=1) == 1
    forged = bytearray(old); forged[11] = 2                                    # ... or just edits the header
    path.write_bytes(bytes(forged))
    with pytest.raises(InvalidTag):
        EncryptedVectorIndex(64).open(path, key, min_version=2)
    path.unlink()                                                              # ... or deletes it
    with pytest.raises(IndexRollback, match="no sealed state"):
        EncryptedVectorIndex(64).open(path, key, min_version=2)
    assert EncryptedVectorIndex(64).open(path, key, min_version=0) == 0        # nothing committed yet: start empty


def test_files_sealed_before_versioning_open_as_version_0(tmp_path):
    from attestrag.common.crypto import seal
    from attestrag.index import FORMAT, IndexRollback
    key, path = new_key(), tmp_path / "legacy.enc"
    idx = EncryptedVectorIndex(8)
    idx.add(np.eye(8, dtype=np.float32)[:1], [{"chunk_id": "x", "doc_id": "d", "text": "x"}])
    import io, json
    buf = io.BytesIO(); np.save(buf, idx._vecs, allow_pickle=False); v = buf.getvalue()
    path.write_bytes(seal(key, len(v).to_bytes(8, "big") + v + json.dumps(idx._payloads).encode(), FORMAT + b"|dim=8"))
    assert EncryptedVectorIndex(8).open(path, key) == 0 and len(EncryptedVectorIndex.load(path, key, 8)) == 1
    with pytest.raises(IndexRollback):
        EncryptedVectorIndex(8).open(path, key, min_version=1)
