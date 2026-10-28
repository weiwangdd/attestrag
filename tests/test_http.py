"""KBS and node over HTTP (mock attestation): the same flow as test_e2e, across sockets."""

import pytest

from attestrag.common.crypto import new_key, open_sealed, seal
from attestrag.embed import HashingEmbedder
from attestrag.generate import StubGenerator
from attestrag.kbs_client import HttpKBS, KBSClient, KeyReleaseDenied, ReferenceKBS, commit_tag, kbs_routes
from attestrag.node import ANSWER_INFO, AttestRAGNode, node_routes
from attestrag.sdk import AttestRAGClient, NodeUntrusted
from attestrag.sdk.http import HttpNodeTransport
from attestrag.transport import HttpError, JsonServer, post_json


@pytest.fixture
def kbs_obj(verifier, policy):
    kbs = ReferenceKBS(verifier, policy)
    kbs.put_key("index-dek", new_key())
    kbs.put_key("acme", new_key(), token=new_key())
    return kbs


@pytest.fixture
def kbs_url(kbs_obj):
    srv = JsonServer(kbs_routes(kbs_obj)).start()
    kbs_obj.url = srv.url
    yield srv.url
    srv.stop()


def make_node(tmp_path, kbs_url, attester, **kw):
    return AttestRAGNode(attester, KBSClient(HttpKBS(kbs_url), attester), HashingEmbedder(256),
                         StubGenerator(), tmp_path / "data", **kw)


@pytest.fixture
def node_url(tmp_path, kbs_url, make_attester):
    node = make_node(tmp_path, kbs_url, make_attester(gpus=1))
    node.start()
    srv = JsonServer(node_routes(node)).start()
    yield srv.url
    srv.stop()


def test_http_end_to_end(node_url, verifier, policy):
    client = AttestRAGClient(HttpNodeTransport(node_url), verifier, policy)
    claims = client.connect()
    assert claims.cpu.measurement == "ab" * 48 and len(claims.gpus) == 1
    assert client.upload("snp", b"The VCEK signs SEV-SNP attestation reports.") == 1
    assert client.upload("cook", b"Toast the rice before adding stock.") == 1
    res = client.ask("Which key signs SNP reports?", k=2)
    assert res["hits"][0]["doc_id"] == "snp" and "VCEK" in res["answer"]["text"]


def test_http_kbs_denies_bad_measurement(tmp_path, kbs_url, make_attester):
    node = make_node(tmp_path, kbs_url, make_attester(measurement="ee" * 48))
    with pytest.raises(KeyReleaseDenied, match="measurement not in allow-list"):
        node.start()


def test_http_kbs_nonce_single_use(kbs_url, make_attester):
    kbs = HttpKBS(kbs_url)
    n, pub = kbs.challenge(), b"\x09" * 32
    ev = make_attester().attest_for(n, pub)
    kbs.request_key("index-dek", n, pub, ev)
    with pytest.raises(KeyReleaseDenied, match="nonce"):
        kbs.request_key("index-dek", n, pub, ev)


def test_http_client_refuses_untrusted_node(tmp_path, kbs_url, make_attester, verifier, policy):
    from attestrag.policy import Policy
    node = make_node(tmp_path, kbs_url, make_attester())
    node.start()
    srv = JsonServer(node_routes(node)).start()
    try:
        strict = Policy(**{**policy.__dict__, "allowed_measurements": frozenset({"ff" * 48})})
        client = AttestRAGClient(HttpNodeTransport(srv.url), verifier, strict)
        with pytest.raises(NodeUntrusted):
            client.connect()
        with pytest.raises(NodeUntrusted):
            client.upload("x", b"secret")
    finally:
        srv.stop()


def test_http_answer_cannot_be_forged(node_url, verifier, policy):
    """A man in the middle who swaps the sealed answer cannot make the client accept it."""
    class Mitm(HttpNodeTransport):
        def query(self, wrapped_question, k=4):
            super().query(wrapped_question, k)
            return seal(new_key(), b'{"answer": {"text": "forged"}, "hits": []}', aad=ANSWER_INFO)
    client = AttestRAGClient(Mitm(node_url), verifier, policy)
    client.connect()
    with pytest.raises(Exception):  # AES-GCM InvalidTag: reply key is known only to the attested node
        client.ask("anything")


def test_http_bad_requests(kbs_url, node_url):
    with pytest.raises(HttpError) as e:
        post_json(f"{kbs_url}/key", {"key_id": "index-dek"})
    assert e.value.status == 400
    with pytest.raises(HttpError) as e:
        post_json(f"{node_url}/nope", {})
    assert e.value.status == 404
    with pytest.raises(HttpError) as e:
        post_json(f"{node_url}/attestation", {"nonce": "zz"})
    assert e.value.status == 400


def test_http_release_signature_and_commits(tmp_path, kbs_obj, kbs_url, make_attester, verifier, policy):
    from attestrag.attest import AttestationError
    from attestrag.kbs_client import VersionCommitRejected
    att = make_attester()
    pinned = KBSClient(HttpKBS(kbs_url), att, kbs_pubkey=kbs_obj.public_key)
    rel = pinned.get_release("acme")
    assert rel.version == 0 and rel.token == kbs_obj.record("acme").token
    with pytest.raises(AttestationError, match="signature"):
        KBSClient(HttpKBS(kbs_url), att, kbs_pubkey=bytes(32)).get_release("acme")   # pinned to someone else
    assert pinned.commit_version("acme", 1, rel.key) == 1
    with pytest.raises(VersionCommitRejected, match="not newer"):
        pinned.commit_version("acme", 1, rel.key)
    with pytest.raises(HttpError) as e:
        post_json(f"{kbs_url}/commit", {"key_id": "acme", "version": 2, "tag": "00" * 32})
    assert e.value.status == 403
    with pytest.raises(HttpError) as e:
        post_json(f"{kbs_url}/commit", {"key_id": "acme", "version": 0, "tag": commit_tag(rel.key, "acme", 0).hex()})
    assert e.value.status == 409
    # the node's own ingest commits over HTTP and reports it
    node = make_node(tmp_path, kbs_url, att); node.start()
    srv = JsonServer(node_routes(node)).start()
    try:
        c = AttestRAGClient(HttpNodeTransport(srv.url), verifier, policy); c.connect()
        c.upload("snp", b"The VCEK signs SEV-SNP attestation reports.")
        assert kbs_obj.version("index-dek") == 1 and node.tenants["index-dek"].committed == 1
        d = post_json(f"{srv.url}/ingest", {"doc_id": "x", "wrapped": {"eph_pub": "00" * 32, "ciphertext": "00"}}) if False else None
    finally:
        srv.stop()


def test_http_tenant_token_is_enforced(tmp_path, kbs_obj, kbs_url, make_attester, verifier, policy):
    node = make_node(tmp_path, kbs_url, make_attester(), tenants=["acme", "index-dek"]); node.start()
    srv = JsonServer(node_routes(node)).start()
    try:
        ok = AttestRAGClient(HttpNodeTransport(srv.url), verifier, policy, tenant="acme", token=kbs_obj.record("acme").token)
        ok.connect()
        assert ok.upload("snp", b"The VCEK signs SEV-SNP attestation reports.") == 1
        assert ok.ask("Which key signs SNP reports?", k=1)["hits"][0]["doc_id"] == "snp"
        bad = AttestRAGClient(HttpNodeTransport(srv.url), verifier, policy, tenant="acme", token=new_key()); bad.connect()
        with pytest.raises(HttpError) as e:
            bad.ask("anything")
        assert e.value.status == 403 and "tenant authentication failed" in str(e.value)
        with pytest.raises(HttpError) as e:
            AttestRAGClient(HttpNodeTransport(srv.url), verifier, policy, tenant="nobody").ask("x") if False else \
                post_json(f"{srv.url}/query", {"tenant": "nobody", "wrapped": {"eph_pub": "00" * 32, "ciphertext": "00"}})
        assert e.value.status == 404
        open_t = AttestRAGClient(HttpNodeTransport(srv.url), verifier, policy); open_t.connect()   # index-dek has no token
        assert open_t.upload("cook", b"Toast the rice before adding stock.") == 1
        assert [h["doc_id"] for h in open_t.ask("rice", k=4)["hits"]] == ["cook"]                  # and its own index
    finally:
        srv.stop()
