import json
from pathlib import Path

import pytest
from cryptography import x509

from attestrag.attest import AttestationError, CompositeVerifier, Evidence, Platform, cpu_report_data
from attestrag.attest import snp
from attestrag.attest.snp import KdsClient, SnpAttester, SnpReport, SnpVerifier
from attestrag.policy import Policy, evaluate
from tests.snp_fixture import (DEFAULT_TCB, FIXED_NOW, FIXTURE_DIR, FakeAmd, FakeKds,
                               build_report)

RD = cpu_report_data(b"n" * 32, b"k" * 32)


# ---------------------------------------------------------------- golden sample

class GoldenKds:
    def __init__(self):
        certs = x509.load_pem_x509_certificates((FIXTURE_DIR / "ask_ark.pem").read_bytes())
        self.ask, self.ark = certs
        self.vcek_cert = x509.load_der_x509_certificate((FIXTURE_DIR / "vcek.der").read_bytes())

    def cert_chain(self, product):
        return self.ask, self.ark

    def vcek(self, product, chip_id, tcb):
        return self.vcek_cert


@pytest.fixture(scope="module")
def golden():
    meta = json.loads((FIXTURE_DIR / "meta.json").read_text())
    v = SnpVerifier(GoldenKds(), ark_pins={meta["product"]: meta["ark_spki_sha256"]},
                    clock=lambda: meta["verify_at"])
    return meta, (FIXTURE_DIR / "report.bin").read_bytes(), v


def test_golden_report_parses(golden):
    meta, raw, _ = golden
    r = SnpReport.parse(raw)
    assert r.version == 3 and r.vmpl == 0 and not r.debug
    assert r.measurement.hex() == meta["measurement"]
    assert snp.decode_tcb(r.reported_tcb, "Milan") == meta["tcb"]
    assert snp.product_from_cpuid(r.cpuid_fam, r.cpuid_mod) == "Milan"


def test_golden_report_verifies_and_maps_claims(golden):
    meta, raw, v = golden
    rd = bytes.fromhex(meta["report_data"])
    c = v.verify(Evidence(Platform.SEV_SNP, raw, b""), rd)
    assert c.platform is Platform.SEV_SNP
    assert c.measurement == meta["measurement"]
    assert c.tcb == meta["tcb"]
    assert c.report_data == rd and not c.debug
    assert c.extra["product"] == "Milan" and c.signer == "amd-milan-vcek"


def test_golden_tamper_any_signed_byte(golden):
    meta, raw, v = golden
    rd = bytes.fromhex(meta["report_data"])
    for off in (0x08, 0x90, 0x180):  # policy, measurement, reported TCB
        bad = bytearray(raw)
        bad[off] ^= 1
        with pytest.raises(AttestationError):
            v.verify(Evidence(Platform.SEV_SNP, bytes(bad), b""), rd)


def test_golden_wrong_report_data(golden):
    _, raw, v = golden
    with pytest.raises(AttestationError, match="report_data"):
        v.verify(Evidence(Platform.SEV_SNP, raw, b""), RD)


def test_golden_rejected_with_real_amd_pins(golden):
    """The synthetic chain must not pass against the real, pinned AMD ARK."""
    meta, raw, _ = golden
    v = SnpVerifier(GoldenKds(), clock=lambda: meta["verify_at"])
    with pytest.raises(AttestationError, match="pinned"):
        v.verify(Evidence(Platform.SEV_SNP, raw, b""), bytes.fromhex(meta["report_data"]))


# ---------------------------------------------------------------- generated variants

@pytest.fixture(scope="module")
def amd():
    return FakeAmd()


def make(amd, *, vcek_tcb=None, chip_id=b"\xc1" * 64, **report_kw):
    key, vcek = amd.make_vcek(chip_id, vcek_tcb or DEFAULT_TCB)
    raw = build_report(key, RD, chip_id=chip_id, **report_kw)
    kds = FakeKds(amd, vcek)
    return raw, vcek, kds, SnpVerifier(kds, ark_pins=amd.pins, clock=lambda: FIXED_NOW)


def verify(v, raw, chain=()):
    return v.verify(Evidence(Platform.SEV_SNP, raw, b"", chain), RD)


def test_debug_guest_flagged_and_denied_by_policy(amd):
    raw, _, _, v = make(amd, policy=0x30000 | snp.POLICY_DEBUG_BIT)
    c = verify(v, raw)
    assert c.debug
    pol = Policy(frozenset({Platform.SEV_SNP}), frozenset({c.measurement}))
    from attestrag.attest import CompositeClaims
    assert "cpu: debug mode enabled" in evaluate(pol, CompositeClaims(c), FIXED_NOW).reasons


def test_vcek_tcb_must_match_reported_tcb(amd):
    raw, _, _, v = make(amd, vcek_tcb={**DEFAULT_TCB, "snp": 23})
    with pytest.raises(AttestationError, match="snp SPL"):
        verify(v, raw)


def test_vcek_for_other_chip_rejected(amd):
    key, vcek = amd.make_vcek(b"\xee" * 64, DEFAULT_TCB)
    raw = build_report(key, RD)  # report claims chip c1..; VCEK is for ee..
    v = SnpVerifier(FakeKds(amd, vcek), ark_pins=amd.pins, clock=lambda: FIXED_NOW)
    with pytest.raises(AttestationError, match="hwID"):
        verify(v, raw)


def test_vcek_from_rogue_ask_rejected(amd):
    rogue = FakeAmd()
    key, vcek = rogue.make_vcek(b"\xc1" * 64, DEFAULT_TCB)
    raw = build_report(key, RD)
    v = SnpVerifier(FakeKds(amd, vcek), ark_pins=amd.pins, clock=lambda: FIXED_NOW)
    with pytest.raises(AttestationError, match="chain"):
        verify(v, raw)


def test_vmpl_above_limit_rejected(amd):
    raw, _, _, v = make(amd, vmpl=2)
    with pytest.raises(AttestationError, match="VMPL"):
        verify(v, raw)


def test_vcek_from_evidence_skips_kds(amd):
    from cryptography.hazmat.primitives import serialization
    raw, vcek, kds, v = make(amd)
    verify(v, raw, (vcek.public_bytes(serialization.Encoding.DER),))
    assert kds.vcek_calls == 0
    verify(v, raw)
    assert kds.vcek_calls == 1


def test_turin_tcb_layout(amd):
    turin = FakeAmd(product=snp.TURIN)
    tcb = {"fmc": 1, "bootloader": 2, "tee": 3, "snp": 4, "microcode": 5}
    key, vcek = turin.make_vcek(b"\xc1" * 8, tcb)
    raw = build_report(key, RD, tcb=tcb, product=snp.TURIN, cpuid=(0x1A, 0x02, 0x00))
    v = SnpVerifier(FakeKds(turin, vcek), ark_pins=turin.pins, clock=lambda: FIXED_NOW)
    assert verify(v, raw).tcb == tcb


def test_v2_report_needs_configured_product(amd):
    raw, _, kds, _ = make(amd, version=2, cpuid=(0, 0, 0))
    with pytest.raises(AttestationError, match="product"):
        verify(SnpVerifier(kds, ark_pins=amd.pins, clock=lambda: FIXED_NOW), raw)
    v = SnpVerifier(kds, product=snp.MILAN, ark_pins=amd.pins, clock=lambda: FIXED_NOW)
    assert verify(v, raw).extra["product"] == "Milan"


def test_composite_verifier_dispatch(amd):
    raw, _, _, v = make(amd)
    cv = CompositeVerifier({Platform.SEV_SNP: v})
    from attestrag.attest import CompositeEvidence
    assert cv.verify(CompositeEvidence(Evidence(Platform.SEV_SNP, raw, b"")), RD).cpu.tcb == DEFAULT_TCB


# ---------------------------------------------------------------- bundled AMD roots / KDS

@pytest.mark.parametrize("product", ["Milan", "Genoa", "Turin"])
def test_bundled_amd_roots_match_pins(product):
    ask, ark = KdsClient(offline=True).cert_chain(product)
    assert snp.spki_sha256(ark) == snp.ARK_SPKI_SHA256[product]
    ark.verify_directly_issued_by(ark)
    ask.verify_directly_issued_by(ark)


def test_kds_vcek_url():
    k = KdsClient(offline=True)
    url = k.vcek_url("Milan", bytes(range(64)), DEFAULT_TCB)
    assert url.startswith("https://kdsintf.amd.com/vcek/v1/Milan/000102")
    assert url.endswith("?blSPL=04&teeSPL=00&snpSPL=22&ucodeSPL=213")
    turl = k.vcek_url("Turin", bytes(range(64)), {"fmc": 1, **DEFAULT_TCB})
    assert "/Turin/0001020304050607?" in turl and turl.endswith("&fmcSPL=01")


def test_kds_cache_is_used(tmp_path):
    k = KdsClient(cache_dir=tmp_path, offline=True)
    url = "https://kdsintf.amd.com/x"
    with pytest.raises(AttestationError, match="offline"):
        k._get(url)
    import hashlib
    (tmp_path / hashlib.sha256(url.encode()).hexdigest()).write_bytes(b"cached")
    assert k._get(url) == b"cached"


# ---------------------------------------------------------------- configfs-tsm attester

class FakeTsm(SnpAttester):
    """Simulates the kernel populating a configfs-tsm report entry."""

    def __init__(self, root, outblob, aux=b"", provider="sev_guest"):
        super().__init__(root)
        self.outblob, self.aux, self.provider, self.seen = outblob, aux, provider, None

    def _create_entry(self, path: Path):
        path.mkdir()
        (path / "provider").write_text(self.provider + "\n")
        (path / "generation").write_text("1\n")
        (path / "outblob").write_bytes(self.outblob)
        if self.aux:
            (path / "auxblob").write_bytes(self.aux)
        self.entry = path

    def attest(self, report_data):
        try:
            return super().attest(report_data)
        finally:
            inblob = self.entry / "inblob"
            self.seen = inblob.read_bytes() if inblob.exists() else None
            for f in self.entry.iterdir():
                f.unlink()
            self.entry.rmdir()


def _cert_table(entries):
    import struct, uuid
    hdr_len = 24 * (len(entries) + 1)
    hdr, body, off = b"", b"", hdr_len
    for guid, data in entries:
        hdr += uuid.UUID(guid).bytes_le + struct.pack("<II", off, len(data))
        body += data
        off += len(data)
    return hdr + bytes(24) + body


def test_configfs_attester_roundtrip(tmp_path, amd):
    from cryptography.hazmat.primitives import serialization
    key, vcek = amd.make_vcek(b"\xc1" * 64, DEFAULT_TCB)
    vcek_der = vcek.public_bytes(serialization.Encoding.DER)
    raw = build_report(key, RD)
    att = FakeTsm(tmp_path, raw, aux=_cert_table([(str(snp.GUID_VCEK), vcek_der)]))
    ev = att.attest(RD)
    assert att.seen == RD.ljust(64, b"\0")
    assert ev.platform is Platform.SEV_SNP and ev.report == raw and ev.cert_chain == (vcek_der,)
    kds = FakeKds(amd, None)  # must not be called: VCEK came via auxblob
    SnpVerifier(kds, ark_pins=amd.pins, clock=lambda: FIXED_NOW).verify(ev, RD)


def test_configfs_wrong_provider(tmp_path):
    with pytest.raises(AttestationError, match="provider"):
        FakeTsm(tmp_path, b"", provider="tdx_guest").attest(RD)


def test_configfs_missing(tmp_path):
    with pytest.raises(AttestationError, match="configfs-tsm"):
        SnpAttester(tmp_path / "nope").attest(RD)


# ---------------------------------------------------------------- real hardware sample (h200, Genoa)

H200_DIR = Path(__file__).parent / "fixtures" / "snp" / "h200-genoa"
POLICY_FILE = Path(__file__).parent.parent / "policies" / "h200-genoa.json"


class H200Kds:
    """Bundled real AMD ARK/ASK; the VCEK is the one KDS returned for this chip + TCB."""

    def __init__(self):
        self.inner = KdsClient(offline=True)
        self.vcek_cert = snp.load_der_cert((H200_DIR / "vcek.der").read_bytes())

    def cert_chain(self, product):
        return self.inner.cert_chain(product)

    def vcek(self, product, chip_id, tcb):
        return self.vcek_cert


@pytest.fixture(scope="module")
def h200():
    meta = json.loads((H200_DIR / "meta.json").read_text())
    v = SnpVerifier(H200Kds(), clock=lambda: meta["verify_at"])  # real pinned AMD ARKs
    return meta, (H200_DIR / "report.bin").read_bytes(), v


def test_h200_report_parses(h200):
    meta, raw, _ = h200
    r = SnpReport.parse(raw)
    assert r.version == meta["report_version"] and r.vmpl == 0 and not r.debug
    assert hex(r.policy) == meta["guest_policy"]
    assert r.measurement.hex() == meta["measurement"]
    assert snp.product_from_cpuid(r.cpuid_fam, r.cpuid_mod) == "Genoa"
    assert snp.decode_tcb(r.reported_tcb, "Genoa") == meta["tcb"]


def test_h200_report_verifies_against_real_amd_roots(h200):
    meta, raw, v = h200
    rd = bytes.fromhex(meta["report_data"])
    c = v.verify(Evidence(Platform.SEV_SNP, raw, b""), rd)
    assert c.signer == "amd-genoa-vcek" and c.measurement == meta["measurement"]
    assert c.tcb == meta["tcb"] and not c.debug
    assert c.extra["guest_policy"] == meta["guest_policy"]
    assert c.extra["launch_tcb"] == meta["launch_tcb"]  # offset 0x1F0, not 0x1F8


def test_h200_policy_file_allows_and_pins(h200):
    from attestrag.attest import CompositeClaims
    meta, raw, v = h200
    c = v.verify(Evidence(Platform.SEV_SNP, raw, b""), bytes.fromhex(meta["report_data"]))
    pol = Policy.from_json(POLICY_FILE.read_text())
    # the published policy requires the GPU half too (tests/test_composite_h200.py has the bound pair)
    assert evaluate(pol, CompositeClaims(c), meta["verify_at"]).reasons == ("gpu: GPU evidence required but none presented",)
    cpu_only = Policy(**{**pol.__dict__, "require_gpu": False})
    assert evaluate(cpu_only, CompositeClaims(c), meta["verify_at"]).allow
    pol = cpu_only
    stricter = Policy(**{**pol.__dict__, "min_tcb": {**pol.min_tcb, "snp": 25}})
    assert "cpu: tcb 'snp'=24 < required 25" in evaluate(stricter, CompositeClaims(c), meta["verify_at"]).reasons
    assert pol.allowed_guest_policy == frozenset({0x30000})
    no_smt = Policy(**{**pol.__dict__, "allowed_guest_policy": frozenset({0x20000})})
    assert "cpu: guest policy 0x30000 not in allow-list" in evaluate(no_smt, CompositeClaims(c), meta["verify_at"]).reasons


def test_h200_tamper_and_wrong_nonce_rejected(h200):
    meta, raw, v = h200
    rd = bytes.fromhex(meta["report_data"])
    for off in (0x08, 0x90):  # policy, measurement -> signature breaks
        bad = bytearray(raw)
        bad[off] ^= 1
        with pytest.raises(AttestationError, match="signature"):
            v.verify(Evidence(Platform.SEV_SNP, bytes(bad), b""), rd)
    bad = bytearray(raw)
    bad[0x180] ^= 1  # reported TCB -> no longer matches the VCEK's SPL extensions
    with pytest.raises(AttestationError, match="SPL"):
        v.verify(Evidence(Platform.SEV_SNP, bytes(bad), b""), rd)
    with pytest.raises(AttestationError, match="report_data"):
        v.verify(Evidence(Platform.SEV_SNP, raw, b""), RD)
