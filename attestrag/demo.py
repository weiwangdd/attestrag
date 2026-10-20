"""Local demo with mock attestation: python -m attestrag.demo"""

from __future__ import annotations

import tempfile

from .attest import CompositeAttester, CompositeVerifier, Platform
from .attest.mock import MockAttester, MockTEEConfig, MockVendor, MockVerifier
from .common.crypto import new_key
from .embed import HashingEmbedder
from .generate import StubGenerator
from .kbs_client import KBSClient, ReferenceKBS
from .node import AttestRAGNode
from .policy import Policy
from .sdk import AttestRAGClient


def main() -> None:
    amd, nv = MockVendor("mock-amd"), MockVendor("mock-nvidia")
    mv = MockVerifier({amd.name: amd.root_public, nv.name: nv.root_public})
    verifier = CompositeVerifier({Platform.MOCK_CPU: mv, Platform.MOCK_GPU: mv})
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
    kbs = ReferenceKBS(verifier, policy)
    kbs.put_key("index-dek", new_key())

    with tempfile.TemporaryDirectory() as d:
        node = AttestRAGNode(attester, KBSClient(kbs, attester), HashingEmbedder(), StubGenerator(), d)
        node.start()
        print("KBS released index key:", kbs.audit[-1])
        client = AttestRAGClient(node, verifier, policy)
        claims = client.connect()
        print("client verified node:", claims.cpu.measurement[:16], "+", len(claims.gpus), "GPU(s)")
        client.upload("snp", b"The VCEK signs SEV-SNP attestation reports.\n\nTDX quotes carry MRTD.")
        res = client.ask("What signs SNP reports?")
        print("answer:", res["answer"]["text"])


if __name__ == "__main__":
    main()
