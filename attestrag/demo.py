"""End-to-end demo.

    python -m attestrag.demo                    # mock attestation, runs anywhere
    sudo python -m attestrag.demo --snp         # real SEV-SNP inside an SNP CVM
    sudo python -m attestrag.demo --snp --dump snp-capture   # also save raw evidence

In --snp mode the KBS still runs in-process (inside the same CVM), which proves
the plumbing but is NOT a meaningful trust setup: in production the KBS runs in
the customer's own trust domain. Without --policy, the demo trusts the first
measurement/TCB it observes (TOFU) and prints that policy so it can be pinned.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from .attest import CompositeAttester, CompositeVerifier, Platform, cpu_report_data
from .common.crypto import new_key
from .embed import HashingEmbedder
from .generate import StubGenerator
from .kbs_client import KBSClient, ReferenceKBS
from .node import AttestRAGNode
from .policy import Policy
from .sdk import AttestRAGClient

DOC = b"The VCEK signs SEV-SNP attestation reports.\n\nTDX quotes carry MRTD."


def run_flow(attester: CompositeAttester, verifier: CompositeVerifier, policy: Policy) -> None:
    kbs = ReferenceKBS(verifier, policy)
    kbs.put_key("index-dek", new_key())
    with tempfile.TemporaryDirectory() as d:
        node = AttestRAGNode(attester, KBSClient(kbs, attester), HashingEmbedder(), StubGenerator(), d)
        node.start()
        rec = kbs.audit[-1]
        print(f"KBS released '{rec.key_id}' to measurement {rec.measurement[:24]}...")
        client = AttestRAGClient(node, verifier, policy)
        claims = client.connect()
        print(f"client verified node: platform={claims.cpu.platform.value} tcb={claims.cpu.tcb} "
              f"gpus={len(claims.gpus)}")
        client.upload("snp", DOC)
        res = client.ask("What signs SNP reports?")
        print("answer:", res["answer"]["text"])


def mock_main() -> None:
    from .attest.mock import MockAttester, MockTEEConfig, MockVendor, MockVerifier

    amd, nv = MockVendor("mock-amd"), MockVendor("mock-nvidia")
    mv = MockVerifier({amd.name: amd.root_public, nv.name: nv.root_public})
    measurement = "ab" * 48
    policy = Policy(
        allowed_cpu_platforms=frozenset({Platform.MOCK_CPU}),
        allowed_measurements=frozenset({measurement}),
        min_tcb={"bootloader": 3, "snp": 8, "microcode": 115},
        require_gpu=True,
        allowed_gpu_platforms=frozenset({Platform.MOCK_GPU}),
        min_gpu_tcb={"driver": 535},
    )
    attester = CompositeAttester(
        MockAttester(amd, MockTEEConfig(measurement=measurement)),
        [MockAttester(nv, MockTEEConfig(Platform.MOCK_GPU, "cd" * 48, {"driver": 550}))],
    )
    run_flow(attester, CompositeVerifier({Platform.MOCK_CPU: mv, Platform.MOCK_GPU: mv}), policy)


def dump_snp_evidence(out: Path, rd: bytes, product: str | None) -> None:
    """Capture one raw SNP report plus its AMD chain in the tests/fixtures/snp layout.

    Written before verification, and best-effort per file, so a report the
    verifier rejects can still be brought home and debugged offline.
    """
    from cryptography.hazmat.primitives import serialization

    from .attest import snp

    out.mkdir(parents=True, exist_ok=True)
    ev = snp.SnpAttester().attest(rd)
    (out / "report.bin").write_bytes(ev.report)
    (out / "evidence.json").write_text(ev.to_json() + "\n")
    meta: dict = {"report_data": rd.hex(), "verify_at": time.time(), "vcek_source": None}
    errors = []
    try:
        r = snp.SnpReport.parse(ev.report)
        p = (snp.product_from_cpuid(r.cpuid_fam, r.cpuid_mod) if r.version >= 3 else None) or product
        meta.update(product=p, report_version=r.version, measurement=r.measurement.hex(),
                    vmpl=r.vmpl, debug=r.debug, policy=hex(r.policy), signing_key=r.signing_key,
                    mask_chip_key=r.mask_chip_key, chip_id=r.chip_id.hex(),
                    cpuid=[r.cpuid_fam, r.cpuid_mod] if r.version >= 3 else None,
                    reported_tcb=hex(r.reported_tcb), current_tcb=hex(r.current_tcb),
                    committed_tcb=hex(r.committed_tcb), launch_tcb=hex(r.launch_tcb))
        if p:
            meta["tcb"] = snp.decode_tcb(r.reported_tcb, p)
            meta["ark_spki_sha256"] = snp.ARK_SPKI_SHA256.get(p)
            kds = snp.KdsClient()
            ask, ark = kds.cert_chain(p)
            (out / "ask_ark.pem").write_bytes(ask.public_bytes(serialization.Encoding.PEM)
                                              + ark.public_bytes(serialization.Encoding.PEM))
            if ev.cert_chain:
                (out / "vcek.der").write_bytes(ev.cert_chain[0])
                meta["vcek_source"] = "auxblob"
            else:
                meta["vcek_url"] = kds.vcek_url(p, r.chip_id, meta["tcb"])
                vcek = kds.vcek(p, r.chip_id, meta["tcb"])
                (out / "vcek.der").write_bytes(vcek.public_bytes(serialization.Encoding.DER))
                meta["vcek_source"] = "kds"
    except Exception as e:  # keep whatever was captured
        errors.append(f"{type(e).__name__}: {e}")
    meta["errors"] = errors
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"captured SNP evidence in {out}" + (f" (errors: {errors})" if errors else ""))


def snp_main(policy_path: str | None, product: str | None, dump: str | None = None) -> None:
    from .attest.snp import SnpAttester, SnpVerifier

    if dump:
        dump_snp_evidence(Path(dump), cpu_report_data(os.urandom(32), bytes(32)), product)
    attester = CompositeAttester(SnpAttester())
    verifier = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(product=product)})
    if policy_path:
        with open(policy_path) as f:
            policy = Policy.from_json(f.read())
    else:
        rd = cpu_report_data(os.urandom(32), bytes(32))
        probe = verifier.verify(attester.attest(rd), rd).cpu
        print("WARNING: no --policy given; trusting observed measurement/TCB (TOFU).", file=sys.stderr)
        observed = {
            "allowed_cpu_platforms": ["sev-snp"],
            "allowed_measurements": [probe.measurement],
            "min_tcb": probe.tcb,
        }
        print("observed policy (save and pass with --policy):")
        print(json.dumps(observed, indent=2))
        print("report extras:", json.dumps(probe.extra, indent=2))
        policy = Policy.from_dict(observed)
    run_flow(attester, verifier, policy)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.demo")
    ap.add_argument("--snp", action="store_true", help="use real SEV-SNP attestation (needs root in an SNP CVM)")
    ap.add_argument("--policy", help="policy JSON file (SNP mode)")
    ap.add_argument("--product", choices=["Milan", "Genoa", "Turin"],
                    help="AMD product, needed only if the report lacks CPUID fields")
    ap.add_argument("--dump", metavar="DIR", help="SNP mode: save a raw report + AMD certs to DIR first")
    args = ap.parse_args(argv)
    if args.snp:
        snp_main(args.policy, args.product, args.dump)
    else:
        mock_main()


if __name__ == "__main__":
    main()
