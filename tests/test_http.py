"""KBS and node over HTTP (mock attestation): the same flow as test_e2e, across sockets."""

import pytest

from attestrag.common.crypto import new_key, open_sealed, seal
from attestrag.embed import HashingEmbedder
from attestrag.generate import StubGenerator
from attestrag.kbs_client import HttpKBS, KBSClient, KeyReleaseDenied, ReferenceKBS, kbs_routes
from attestrag.node import ANSWER_INFO, AttestRAGNode, node_routes
from attestrag.sdk import AttestRAGClient, NodeUntrusted
from attestrag.sdk.http import HttpNodeTransport
from attestrag.transport import HttpError, JsonServer, post_json


@pytest.fixture
def kbs_url(verifier, policy):
    kbs = ReferenceKBS(verifier, policy)
    kbs.put_key("index-dek", new_key())
    srv = JsonServer(kbs_routes(kbs)).start()
    yield srv.url
    srv.stop()


def make_node(tmp_path, kbs_url, attester):
    return AttestRAGNode(attester, KBSClient(HttpKBS(kbs_url), attester), HashingEmbedder(256),
                         StubGenerator(), tmp_path / "data")


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
