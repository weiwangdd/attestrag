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
    assert key == kbs._keys["dek"]
    assert kbs.audit[-1].allowed


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
