"""End-to-end demo.

    python -m attestrag.demo                    # mock attestation, runs anywhere
    sudo python -m attestrag.demo --snp         # real SEV-SNP inside an SNP CVM

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


def snp_main(policy_path: str | None, product: str | None, gpu: list[str] | None = None) -> None:
    from .attest.nvidia import NvidiaAttester, NvidiaVerifier, gpu_indices
    from .attest.snp import SnpAttester, SnpVerifier

    gpus = gpu_indices(gpu or [])
    print(f"GPU attesters: {gpus or 'none'}", file=sys.stderr)
    attester = CompositeAttester(SnpAttester(), [NvidiaAttester(i) for i in gpus])
    verifier = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(product=product), Platform.NVIDIA_CC: NvidiaVerifier()})
    if policy_path:
        with open(policy_path) as f:
            policy = Policy.from_json(f.read())
    else:
        rd = cpu_report_data(os.urandom(32), bytes(32))
        claims = verifier.verify(attester.attest(rd), rd)
        probe = claims.cpu
        print("WARNING: no --policy given; trusting observed measurement/TCB (TOFU).", file=sys.stderr)
        observed = {
            "allowed_cpu_platforms": ["sev-snp"],
            "allowed_measurements": [probe.measurement],
            "min_tcb": probe.tcb,
        }
        if claims.gpus:
            observed.update({"require_gpu": True, "allowed_gpu_platforms": ["nvidia-cc"],
                             "allowed_gpu_measurements": sorted({g.measurement for g in claims.gpus})})
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
    ap.add_argument("--gpu", action="append", default=[], metavar="INDEX|auto",
                    help="SNP mode: also attest this NVIDIA CC GPU (repeatable; auto = every CC GPU found)")
    args = ap.parse_args(argv)
    if args.snp:
        snp_main(args.policy, args.product, args.gpu)
    else:
        mock_main()


if __name__ == "__main__":
    main()
