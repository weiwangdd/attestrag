"""Synthetic SEV-SNP evidence with a fake ARK -> ASK -> VCEK chain.

Byte layout and certificate profile mirror real AMD artifacts, but every key is
generated here, so the verifier must be configured with the fake ARK pin.

Regenerate the committed golden sample with:
    .venv/bin/python -m tests.snp_fixture
"""

from __future__ import annotations

import datetime as dt
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from attestrag.attest import snp

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "snp"
NOT_BEFORE = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2045, 1, 1, tzinfo=dt.timezone.utc)
FIXED_NOW = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc).timestamp()
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Micro Devices")])


def _der_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return bytes([0x02, len(b)]) + b


def _cert(subject, issuer, pub, signer, serial, exts=()):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(serial).not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER))
    for e in exts:
        b = b.add_extension(e, critical=False)
    return b.sign(signer, hashes.SHA384(), rsa_padding=PSS)


@dataclass
class FakeAmd:
    product: str = snp.MILAN
    ark_key: rsa.RSAPrivateKey = field(default_factory=lambda: rsa.generate_private_key(65537, 2048))
    ask_key: rsa.RSAPrivateKey = field(default_factory=lambda: rsa.generate_private_key(65537, 2048))

    def __post_init__(self):
        self.ark = _cert(_name(f"ARK-{self.product}"), _name(f"ARK-{self.product}"),
                         self.ark_key.public_key(), self.ark_key, 1)
        self.ask = _cert(_name(f"SEV-{self.product}"), _name(f"ARK-{self.product}"),
                         self.ask_key.public_key(), self.ark_key, 2)

    @property
    def pins(self) -> dict[str, str]:
        return {self.product: snp.spki_sha256(self.ark)}

    def make_vcek(self, chip_id: bytes, tcb: dict[str, int]):
        key = ec.generate_private_key(ec.SECP384R1())
        exts = [x509.UnrecognizedExtension(x509.ObjectIdentifier(snp.OID_HWID), chip_id)]
        exts += [x509.UnrecognizedExtension(x509.ObjectIdentifier(snp.TCB_OIDS[k]), _der_int(v))
                 for k, v in tcb.items()]
        cert = _cert(_name("SEV-VCEK"), _name(f"SEV-{self.product}"), key.public_key(),
                     self.ask_key, 3, exts)
        return key, cert


DEFAULT_TCB = {"bootloader": 4, "tee": 0, "snp": 22, "microcode": 213}


def build_report(vcek_key, report_data: bytes, *, measurement=b"\x5a" * 48,
                 tcb=None, product=snp.MILAN, chip_id=b"\xc1" * 64, policy=0x30000,
                 vmpl=0, version=3, cpuid=(0x19, 0x01, 0x01)) -> bytes:
    tcb = tcb or DEFAULT_TCB
    t = snp.encode_tcb(tcb, product)
    r = bytearray(snp.REPORT_SIZE)
    struct.pack_into("<IIQ", r, 0x00, version, 1, policy)
    struct.pack_into("<II", r, 0x30, vmpl, snp.SIG_ALGO_ECDSA_P384_SHA384)
    struct.pack_into("<QQ", r, 0x38, t, 0)
    r[0x50:0x90] = report_data.ljust(64, b"\0")
    r[0x90:0xC0] = measurement
    struct.pack_into("<Q", r, 0x180, t)
    r[0x188:0x18B] = bytes(cpuid)
    r[0x1A0:0x1E0] = chip_id
    struct.pack_into("<Q", r, 0x1E0, t)
    struct.pack_into("<Q", r, 0x1F8, t)
    sig = vcek_key.sign(bytes(r[: snp.SIGNED_LEN]), ec.ECDSA(hashes.SHA384()))
    rr, ss = decode_dss_signature(sig)
    r[0x2A0:0x2A0 + 72] = rr.to_bytes(72, "little")
    r[0x2A0 + 72:0x2A0 + 144] = ss.to_bytes(72, "little")
    return bytes(r)


class FakeKds:
    def __init__(self, amd: FakeAmd, vcek: x509.Certificate | None):
        self.amd, self._vcek, self.vcek_calls = amd, vcek, 0

    def cert_chain(self, product):
        return self.amd.ask, self.amd.ark

    def vcek(self, product, chip_id, tcb):
        self.vcek_calls += 1
        if self._vcek is None:
            raise AssertionError("unexpected KDS fetch")
        return self._vcek


def write_golden() -> None:
    from attestrag.attest.binding import cpu_report_data

    amd = FakeAmd()
    key, vcek = amd.make_vcek(b"\xc1" * 64, DEFAULT_TCB)
    rd = cpu_report_data(b"golden-nonce".ljust(32, b"\0"), b"\x11" * 32)
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    (FIXTURE_DIR / "report.bin").write_bytes(build_report(key, rd))
    (FIXTURE_DIR / "vcek.der").write_bytes(vcek.public_bytes(serialization.Encoding.DER))
    (FIXTURE_DIR / "ask_ark.pem").write_bytes(
        amd.ask.public_bytes(serialization.Encoding.PEM) + amd.ark.public_bytes(serialization.Encoding.PEM))
    (FIXTURE_DIR / "meta.json").write_text(json.dumps({
        "product": amd.product, "report_data": rd.hex(), "ark_spki_sha256": amd.pins[amd.product],
        "measurement": ("5a" * 48), "tcb": DEFAULT_TCB, "verify_at": FIXED_NOW,
    }, indent=2) + "\n")


if __name__ == "__main__":
    write_golden()
    print("wrote", FIXTURE_DIR)
