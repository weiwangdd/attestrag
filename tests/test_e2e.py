"""Milestone 1: verify -> release key -> encrypted ingest -> retrieve -> generate."""

import pytest

from attestrag.common.crypto import new_key
from attestrag.embed import HashingEmbedder
from attestrag.generate import StubGenerator
from attestrag.kbs_client import KBSClient, KeyReleaseDenied, ReferenceKBS
from attestrag.node import AttestRAGNode
from attestrag.sdk import AttestRAGClient, NodeUntrusted

DOCS = {
    "snp": b"AMD SEV-SNP protects guest memory with per-VM keys.\n\n"
           b"The VCEK signs attestation reports and is derived from the chip's TCB version.",
    "tdx": b"Intel TDX isolates trust domains. The quote includes MRTD and RTMR registers.",
    "cooking": b"To make risotto, toast the rice before adding stock gradually.",
}


def make_node(tmp_path, kbs, attester):
    return AttestRAGNode(attester, KBSClient(kbs, attester), HashingEmbedder(256), StubGenerator(),
                         tmp_path / "data")


@pytest.fixture
def kbs(verifier, policy):
    k = ReferenceKBS(verifier, policy)
    k.put_key("index-dek", new_key())
    return k


def test_end_to_end(tmp_path, kbs, make_attester, verifier, policy):
    node = make_node(tmp_path, kbs, make_attester(gpus=1))
    node.start()

    client = AttestRAGClient(node, verifier, policy)
    claims = client.connect()
    assert claims.cpu.measurement == "ab" * 48 and len(claims.gpus) == 1

    for doc_id, data in DOCS.items():
        assert client.upload(doc_id, data) >= 1

    raw = node.index_path.read_bytes()
    assert b"VCEK" not in raw and b"risotto" not in raw

    res = client.ask("Which key signs SEV-SNP attestation reports?", k=2)
    assert res["hits"][0]["doc_id"] == "snp"
    assert "VCEK" in res["answer"]["text"]
    assert res["answer"]["citations"] == [res["hits"][0]["chunk_id"]]

    # Restart: a fresh node (new transport key) re-attests and reopens the same index.
    node2 = make_node(tmp_path, kbs, make_attester())
    node2.start()
    assert len(node2.index) == len(node.index)
    c2 = AttestRAGClient(node2, verifier, policy)
    c2.connect()
    assert c2.ask("risotto rice")["hits"][0]["doc_id"] == "cooking"


def test_untrusted_node_gets_no_key_and_no_data(tmp_path, kbs, make_attester, verifier, policy):
    evil = make_attester(measurement="ee" * 48)
    node = make_node(tmp_path, kbs, evil)
    with pytest.raises(KeyReleaseDenied):
        node.start()
    client = AttestRAGClient(node, verifier, policy)
    with pytest.raises(NodeUntrusted):
        client.connect()
    with pytest.raises(NodeUntrusted):
        client.upload("x", b"secret")  # SDK refuses before any bytes leave the client
