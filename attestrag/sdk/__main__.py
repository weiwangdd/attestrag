"""Command-line client: verify the node's SEV-SNP evidence against a policy, then upload / ask.

    python -m attestrag.sdk --node http://127.0.0.1:8081 --policy policies/h200-genoa.json upload doc.txt
    python -m attestrag.sdk --node http://127.0.0.1:8081 --policy policies/h200-genoa.json ask "question"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..attest import CompositeVerifier, Platform
from ..attest.snp import KdsClient, SnpVerifier
from ..attest.nvidia import NvidiaVerifier
from ..policy import Policy
from . import AttestRAGClient, NodeUntrusted
from .http import HttpNodeTransport


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.sdk")
    ap.add_argument("--node", required=True, help="node base URL")
    ap.add_argument("--policy", required=True, help="policy JSON the client enforces before sending data")
    ap.add_argument("--product", choices=["Milan", "Genoa", "Turin"])
    ap.add_argument("--kds-cache")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ap.add_argument("--insecure-mock", action="store_true",
                    help="also trust the public insecure-baseline mock vendor (unprotected baseline only; proves nothing)")
    sub.add_parser("verify", help="only verify the node's evidence and print claims")
    up = sub.add_parser("upload"); up.add_argument("file"); up.add_argument("--id"); up.add_argument("--type", default="text/plain")
    ask = sub.add_parser("ask"); ask.add_argument("question"); ask.add_argument("-k", type=int, default=4)
    args = ap.parse_args(argv)

    verifier = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(KdsClient(args.kds_cache), product=args.product),
                                   Platform.NVIDIA_CC: NvidiaVerifier()})
    if args.insecure_mock:
        from .attest.mock import insecure_baseline_verifier
        print("WARNING: --insecure-mock: accepting evidence from the public mock vendor; nothing is protected", file=sys.stderr)
        verifier = CompositeVerifier({**verifier.verifiers, Platform.MOCK_CPU: insecure_baseline_verifier()})
    client = AttestRAGClient(HttpNodeTransport(args.node), verifier, Policy.from_json(Path(args.policy).read_text()))
    try:
        c = client.connect()
    except NodeUntrusted as e:
        print(f"node untrusted, nothing sent: {e}", file=sys.stderr)
        sys.exit(3)
    print(f"node verified: {c.cpu.signer} measurement={c.cpu.measurement[:24]}... tcb={c.cpu.tcb} "
          f"guest_policy={c.cpu.extra.get('guest_policy')}", file=sys.stderr)
    if args.cmd == "verify":
        print(json.dumps({"measurement": c.cpu.measurement, "tcb": c.cpu.tcb, "extra": c.cpu.extra}, indent=2))
    elif args.cmd == "upload":
        n = client.upload(args.id or Path(args.file).name, Path(args.file).read_bytes(), args.type)
        print(f"uploaded {args.file}: {n} chunks")
    else:
        res = client.ask(args.question, args.k)
        print(res["answer"]["text"])
        for h in res["hits"]:
            print(f"  [{h['chunk_id']}] {h['doc_id']} score={h['score']:.3f}", file=sys.stderr)


if __name__ == "__main__":
    main()
