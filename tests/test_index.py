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
