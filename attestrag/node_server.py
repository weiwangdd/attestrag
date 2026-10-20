"""The AttestRAG node as an HTTP service. Runs INSIDE the SEV-SNP CVM (root, for configfs-tsm).

    sudo python -m attestrag.node_server --kbs http://10.0.2.2:8800 --data-dir /var/lib/attestrag

Boot: attest to the KBS, receive the index key, open/create the encrypted index.
Then serve /attestation, /ingest, /query (see node.node_routes).
"""

from __future__ import annotations

import argparse
import sys

from .attest import CompositeAttester
from .attest.snp import SnpAttester
from .embed import HashingEmbedder
from .generate import OpenAICompatibleGenerator, StubGenerator
from .kbs_client import HttpKBS, KBSClient, KeyReleaseDenied
from .node import AttestRAGNode, node_routes
from .transport import JsonServer


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.node_server")
    ap.add_argument("--listen", default="0.0.0.0:8080")
    ap.add_argument("--kbs", required=True, help="KBS base URL, e.g. http://10.0.2.2:8800")
    ap.add_argument("--data-dir", default="/var/lib/attestrag")
    ap.add_argument("--key-id", default="index-dek")
    ap.add_argument("--llm", help="OpenAI-compatible endpoint for generation (default: extractive stub)")
    ap.add_argument("--model", default="local")
    ap.add_argument("--embed-dim", type=int, default=512)
    args = ap.parse_args(argv)

    attester = CompositeAttester(SnpAttester())
    gen = OpenAICompatibleGenerator(args.llm, model=args.model) if args.llm else StubGenerator()
    node = AttestRAGNode(attester, KBSClient(HttpKBS(args.kbs), attester), HashingEmbedder(args.embed_dim),
                         gen, args.data_dir, index_key_id=args.key_id)
    try:
        node.start()
    except KeyReleaseDenied as e:
        print(f"[node] KBS refused to release {args.key_id!r}: {e}", file=sys.stderr)
        sys.exit(3)
    print(f"[node] key {args.key_id!r} released; index has {len(node.index or [])} chunks at {node.index_path}",
          file=sys.stderr, flush=True)
    host, port = args.listen.rsplit(":", 1)
    srv = JsonServer(node_routes(node), (host, int(port)))
    print(f"[node] listening on {srv.url}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
