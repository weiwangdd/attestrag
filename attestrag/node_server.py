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
from .embed import HashingEmbedder, OpenAIEmbedder
from .generate import OpenAICompatibleGenerator, StubGenerator
from .kbs_client import HttpKBS, KBSClient, KeyReleaseDenied
from .node import AttestRAGNode, node_routes
from .transport import JsonServer


def _wait_http(url: str, timeout: float) -> None:
    import time
    import urllib.request
    deadline = time.time() + timeout
    while True:
        try:
            urllib.request.urlopen(url, timeout=5).read()
            return
        except Exception as e:  # noqa: BLE001
            if time.time() > deadline:
                print(f"[node] {url} not ready after {timeout:.0f}s: {e}", file=sys.stderr)
                sys.exit(4)
            time.sleep(2)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.node_server")
    ap.add_argument("--listen", default="0.0.0.0:8080")
    ap.add_argument("--kbs", required=True, help="KBS base URL, e.g. http://10.0.2.2:8800")
    ap.add_argument("--data-dir", default="/var/lib/attestrag")
    ap.add_argument("--key-id", default="index-dek")
    ap.add_argument("--llm", help="OpenAI-compatible /v1 endpoint for generation (default: extractive stub)")
    ap.add_argument("--model", default="local")
    ap.add_argument("--embed", help="OpenAI-compatible /v1 endpoint for embeddings (default: hashing embedder)")
    ap.add_argument("--embed-model", default="local")
    ap.add_argument("--embed-dim", type=int, default=512, help="hashing embedder dimension")
    ap.add_argument("--wait", type=float, default=120.0, help="seconds to wait for --llm/--embed/--qdrant-url to come up")
    ap.add_argument("--vector-store", choices=["sealed", "qdrant"], default="sealed",
                    help="sealed = in-memory index persisted as one AES-GCM blob; qdrant = Qdrant in the CVM (tmpfs storage, sealed snapshots)")
    ap.add_argument("--qdrant-url", default="http://127.0.0.1:6333")
    ap.add_argument("--qdrant-collection", default="attestrag")
    args = ap.parse_args(argv)

    attester = CompositeAttester(SnpAttester())
    for url in (args.llm, args.embed):
        if url:
            _wait_http(url.rstrip("/") + "/models", args.wait)
    gen = OpenAICompatibleGenerator(args.llm, model=args.model) if args.llm else StubGenerator()
    emb = OpenAIEmbedder(args.embed, model=args.embed_model) if args.embed else HashingEmbedder(args.embed_dim)
    print(f"[node] embedder={type(emb).__name__} dim={emb.dim} generator={type(gen).__name__}",
          file=sys.stderr, flush=True)
    store = None
    if args.vector_store == "qdrant":
        from .index.qdrant import QdrantStore
        _wait_http(args.qdrant_url.rstrip("/") + "/healthz", args.wait)
        store = QdrantStore(args.qdrant_url, args.qdrant_collection, dim=emb.dim)
        print(f"[node] vector store=QdrantStore url={args.qdrant_url} collection={args.qdrant_collection}",
              file=sys.stderr, flush=True)
    node = AttestRAGNode(attester, KBSClient(HttpKBS(args.kbs), attester), emb,
                         gen, args.data_dir, index_key_id=args.key_id, store=store)
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
