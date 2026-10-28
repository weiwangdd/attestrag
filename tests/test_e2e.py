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


def make_node(tmp_path, kbs, attester, **kw):
    return AttestRAGNode(attester, KBSClient(kbs, attester, kbs_pubkey=kbs.public_key), HashingEmbedder(256),
                         StubGenerator(), tmp_path / "data", **kw)


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


def test_relevance_gate_refuses_without_calling_the_generator(tmp_path, kbs, make_attester, verifier, policy):
    from attestrag.node import GATE_TEXT
    node = AttestRAGNode(make_attester(), KBSClient(kbs, make_attester()), HashingEmbedder(256), StubGenerator(),
                         tmp_path / "data", min_score=0.5)
    node.start()
    client = AttestRAGClient(node, verifier, policy)
    client.connect()
    for doc_id, data in DOCS.items():
        client.upload(doc_id, data)
    on_topic = client.ask("The VCEK signs attestation reports and is derived from the chip's TCB version.", k=2)
    assert on_topic["gate"]["rejected"] is False and on_topic["gate"]["top_score"] >= 0.5 and "VCEK" in on_topic["answer"]["text"]
    off_topic = client.ask("Quarterly revenue of a bicycle manufacturer in Lisbon", k=2)
    assert off_topic["gate"]["rejected"] is True and off_topic["gate"]["top_score"] < 0.5
    assert off_topic["answer"]["text"] == GATE_TEXT and off_topic["answer"]["model"] == "gate" and off_topic["answer"]["citations"] == []
    assert len(off_topic["hits"]) == 2      # the retrieval result is still reported, the generator is not called


def test_judge_gate_with_the_stub(tmp_path, kbs, make_attester, verifier, policy):
    from attestrag.node import GATE_TEXT
    node = AttestRAGNode(make_attester(), KBSClient(kbs, make_attester()), HashingEmbedder(256), StubGenerator(),
                         tmp_path / "data", judge=True)
    node.start()
    client = AttestRAGClient(node, verifier, policy)
    client.connect()
    for doc_id, data in DOCS.items():
        client.upload(doc_id, data)
    ok = client.ask("Which key signs attestation reports?", k=2)        # "attestation" and "reports" are in the chunk
    assert ok["gate"]["rejected"] is False and ok["gate"]["judge"] is True
    no = client.ask("What is the capital of Portugal?", k=2)
    assert no["gate"] == {**no["gate"], "rejected": True, "reason": "judge"} and no["answer"]["text"] == GATE_TEXT


def test_index_rollback_is_refused_at_start(tmp_path, kbs, make_attester, verifier, policy):
    """The host keeps yesterday's validly sealed snapshot and puts it back: the node must not serve it."""
    import shutil
    from attestrag.index import IndexRollback
    node = make_node(tmp_path, kbs, make_attester())
    node.start()
    client = AttestRAGClient(node, verifier, policy); client.connect()
    client.upload("snp", DOCS["snp"])
    assert kbs.version("index-dek") == 1 and node.tenants["index-dek"].committed == 1
    shutil.copy(node.index_path, tmp_path / "yesterday.enc")
    client.upload("retracted", b"The contract with ACME was cancelled on 2026-10-01.")
    assert kbs.version("index-dek") == 2
    assert client.ask("ACME contract cancelled", k=1)["hits"][0]["doc_id"] == "retracted"

    shutil.copy(tmp_path / "yesterday.enc", node.index_path)       # rollback: version 1 under the same DEK
    with pytest.raises(IndexRollback, match="version 1 .* committed version 2"):
        make_node(tmp_path, kbs, make_attester()).start()
    node.index_path.unlink()                                        # or the host "loses" the file
    with pytest.raises(IndexRollback, match="no sealed state"):
        make_node(tmp_path, kbs, make_attester()).start()
    # the operator's reset at the KBS is the only way back to an empty index
    kbs.put_key("index-dek", kbs.record("index-dek").key, version=0)
    n3 = make_node(tmp_path, kbs, make_attester()); n3.start()
    assert len(n3.index) == 0


def test_newer_snapshot_than_the_kbs_record_is_recommitted(tmp_path, kbs, make_attester, verifier, policy):
    """Sealed to disk but the commit never reached the KBS (crash, KBS down): forward, so accepted, and the KBS catches up."""
    node = make_node(tmp_path, kbs, make_attester()); node.start()
    client = AttestRAGClient(node, verifier, policy); client.connect()
    client.upload("snp", DOCS["snp"])
    kbs.put_key("index-dek", kbs.record("index-dek").key, version=0)      # the KBS "forgot" the commit
    n2 = make_node(tmp_path, kbs, make_attester()); n2.start()
    assert n2.tenants["index-dek"].version == 1 and kbs.version("index-dek") == 1


def test_tenants_are_isolated_and_authenticated(tmp_path, kbs, make_attester, verifier, policy):
    from attestrag.node import TenantAuthError, UnknownTenant
    kbs.put_key("acme", new_key(), token=new_key())
    kbs.put_key("globex", new_key(), token=new_key())
    node = make_node(tmp_path, kbs, make_attester(), tenants=["acme", "globex"]); node.start()
    assert {t.path.name for t in node.tenants.values()} == {"index-acme.enc", "index-globex.enc"}
    acme = AttestRAGClient(node, verifier, policy, tenant="acme", token=kbs.record("acme").token); acme.connect()
    globex = AttestRAGClient(node, verifier, policy, tenant="globex", token=kbs.record("globex").token); globex.connect()
    acme.upload("snp", DOCS["snp"])
    globex.upload("cooking", DOCS["cooking"])
    assert kbs.version("acme") == 1 and kbs.version("globex") == 1
    # each tenant retrieves only from its own index
    assert acme.ask("Which key signs SEV-SNP attestation reports?", k=4)["hits"][0]["doc_id"] == "snp"
    g = globex.ask("Which key signs SEV-SNP attestation reports?", k=4)
    assert [h["doc_id"] for h in g["hits"]] == ["cooking"] and g["tenant"] == "globex"
    # the wrong token, no token, or another tenant's token: refused before anything is decrypted
    for bad in (new_key(), None, kbs.record("globex").token):
        c = AttestRAGClient(node, verifier, policy, tenant="acme", token=bad); c.connect()
        with pytest.raises(TenantAuthError):
            c.upload("x", b"injected")
        with pytest.raises(TenantAuthError):
            c.ask("anything")
    with pytest.raises(UnknownTenant):
        c = AttestRAGClient(node, verifier, policy, tenant="initech", token=new_key()); c.connect(); c.ask("x")
    # a host that re-routes acme's authenticated request to globex: the tag binds the tenant name
    class Reroute:
        def __init__(self, n): self.n = n
        def attestation(self, nonce): return self.n.attestation(nonce)
        def ingest(self, doc_id, wrapped, content_type="text/plain", tenant=None, auth=None):
            return self.n.ingest(doc_id, wrapped, content_type, tenant="globex", auth=auth)
        def query(self, wq, k=4, tenant=None, auth=None):
            return self.n.query(wq, k, tenant="globex", auth=auth)
    r = AttestRAGClient(Reroute(node), verifier, policy, tenant="acme", token=kbs.record("acme").token); r.connect()
    with pytest.raises(TenantAuthError):
        r.upload("x", b"for acme only")
    assert len(node.tenants["globex"].store) == 1


def test_open_tenant_without_token_still_cannot_be_rerouted(tmp_path, kbs, make_attester, verifier, policy):
    """A tenant without a token accepts anyone (benchmarks), but the wrap info still names the tenant."""
    from cryptography.exceptions import InvalidTag
    kbs.put_key("open", new_key())
    kbs.put_key("other", new_key())
    node = make_node(tmp_path, kbs, make_attester(), tenants=["open", "other"]); node.start()
    c = AttestRAGClient(node, verifier, policy, tenant="open"); c.connect()
    assert c.upload("snp", DOCS["snp"]) >= 1
    class Reroute:
        def __init__(self, n): self.n = n
        def attestation(self, nonce): return self.n.attestation(nonce)
        def ingest(self, doc_id, wrapped, content_type="text/plain", tenant=None, auth=None):
            return self.n.ingest(doc_id, wrapped, content_type, tenant="other", auth=auth)
        def query(self, wq, k=4, tenant=None, auth=None):
            return self.n.query(wq, k, tenant="other", auth=auth)
    r = AttestRAGClient(Reroute(node), verifier, policy, tenant="open"); r.connect()
    with pytest.raises(InvalidTag):
        r.upload("x", b"meant for the open tenant")
    assert len(node.tenants["other"].store) == 0
