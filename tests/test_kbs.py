import pytest

from attestrag.common.crypto import new_key
from attestrag.kbs_client import KBSClient, KeyReleaseDenied, ReferenceKBS


@pytest.fixture
def kbs(verifier, policy):
    k = ReferenceKBS(verifier, policy)
    k.put_key("dek", new_key())
    return k


def test_release_to_good_tee(kbs, make_attester):
    key = KBSClient(kbs, make_attester()).get_key("dek")
    assert key == kbs.record("dek").key
    assert kbs.audit[-1].allowed


def test_release_is_signed_by_the_kbs_identity(kbs, make_attester):
    """A node that pins the KBS identity refuses a release signed by anyone else (host-in-the-middle key substitution)."""
    from attestrag.attest import AttestationError
    from attestrag.kbs_client import KeyRelease, verify_release
    good = KBSClient(kbs, make_attester(), kbs_pubkey=kbs.public_key)
    rel = good.get_release("dek")
    assert rel.key == kbs.record("dek").key and rel.version == 0 and rel.token is None

    class Mitm:   # forwards challenges, replaces the release with one wrapped to the same pk by an impostor KBS
        def __init__(self, inner, impostor):
            self.inner, self.impostor = inner, impostor
        def challenge(self):
            n = self.inner.challenge(); self.impostor._nonces[n] = self.impostor.clock() + 60; return n
        def request_key(self, key_id, nonce, pk, ev):
            self.inner.request_key(key_id, nonce, pk, ev)
            return self.impostor.request_key(key_id, nonce, pk, ev)
        def commit_version(self, *a):
            return self.inner.commit_version(*a)
    impostor = ReferenceKBS(kbs.verifier, kbs.policy)
    impostor.put_key("dek", new_key())
    with pytest.raises(AttestationError, match="KBS release signature"):
        KBSClient(Mitm(kbs, impostor), make_attester(), kbs_pubkey=kbs.public_key).get_release("dek")
    # ... whereas without the pin the substituted key is accepted silently (what the old protocol did)
    assert KBSClient(Mitm(kbs, impostor), make_attester()).get_key("dek") == impostor.record("dek").key
    # the signature covers the session: same release replayed under another nonce / pk fails
    n = kbs.challenge(); pk = b"\x07" * 32
    rel2 = kbs.request_key("dek", n, pk, make_attester().attest_for(n, pk))
    verify_release(kbs.public_key, "dek", n, pk, rel2)
    with pytest.raises(AttestationError):
        verify_release(kbs.public_key, "dek", bytes(32), pk, rel2)
    with pytest.raises(AttestationError):
        verify_release(kbs.public_key, "dek", n, bytes(32), rel2)
    with pytest.raises(AttestationError):
        verify_release(kbs.public_key, "other", n, pk, KeyRelease(rel2.wrapped, rel2.signature))


def test_version_commit_needs_the_key_and_moves_forward_only(kbs, make_attester):
    from attestrag.kbs_client import VersionCommitRejected, commit_tag
    seen = []
    kbs.on_change = lambda recs: seen.append(recs["dek"].version)
    client = KBSClient(kbs, make_attester(), kbs_pubkey=kbs.public_key)
    rel = client.get_release("dek")
    assert client.commit_version("dek", 1, rel.key) == 1 and kbs.version("dek") == 1 and seen == [1]
    with pytest.raises(VersionCommitRejected, match="not newer"):
        client.commit_version("dek", 1, rel.key)
    with pytest.raises(VersionCommitRejected, match="tag"):
        kbs.commit_version("dek", 2, commit_tag(new_key(), "dek", 2))      # not the holder of the DEK
    with pytest.raises(VersionCommitRejected, match="tag"):
        kbs.commit_version("dek", 2, commit_tag(rel.key, "dek", 3))        # tag for another version
    assert client.commit_version("dek", 5, rel.key) == 5                   # gaps are fine, only direction matters
    assert client.get_release("dek").version == 5                          # the next release carries it
    kbs.put_key("tenant", new_key(), version=3, token=b"t" * 32)
    r = client.get_release("tenant")
    assert (r.version, r.token) == (3, b"t" * 32)


def test_deny_bad_measurement(kbs, make_attester):
    with pytest.raises(KeyReleaseDenied, match="measurement"):
        KBSClient(kbs, make_attester(measurement="00" * 48)).get_key("dek")
    assert not kbs.audit[-1].allowed


def test_deny_old_tcb(kbs, make_attester):
    with pytest.raises(KeyReleaseDenied, match="microcode"):
        KBSClient(kbs, make_attester(tcb={"bootloader": 3, "snp": 8, "microcode": 100})).get_key("dek")


def test_nonce_single_use(kbs, make_attester):
    att = make_attester()
    n = kbs.challenge()
    pub = b"\x09" * 32
    ev = att.attest_for(n, pub)
    kbs.request_key("dek", n, pub, ev)
    with pytest.raises(KeyReleaseDenied, match="nonce"):
        kbs.request_key("dek", n, pub, ev)


def test_key_bound_to_attested_pubkey(kbs, make_attester):
    """Evidence for pubkey A cannot be used to get the key wrapped to pubkey B."""
    n = kbs.challenge()
    ev = make_attester().attest_for(n, b"A" * 32)
    with pytest.raises(KeyReleaseDenied, match="report_data"):
        kbs.request_key("dek", n, b"B" * 32, ev)
