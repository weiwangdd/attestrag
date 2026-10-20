"""Key Broker Service over HTTP. Runs OUTSIDE the CVM, in the data owner's trust domain.

    python -m attestrag.kbs_server --policy policies/h200-genoa.json --keys kbs-keys.json

Releases a key only to a TEE whose SEV-SNP evidence verifies and passes the policy;
the key is wrapped to the X25519 public key bound into the attestation report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .attest import CompositeVerifier, Platform
from .attest.snp import KdsClient, SnpVerifier
from .common.crypto import new_key
from .kbs_client import ReferenceKBS, kbs_routes
from .policy import Policy
from .transport import JsonServer


def load_keys(path: Path, create: tuple[str, ...]) -> dict[str, bytes]:
    keys = {k: bytes.fromhex(v) for k, v in json.loads(path.read_text()).items()} if path.exists() else {}
    changed = False
    for k in create:
        if k not in keys:
            keys[k] = new_key()
            changed = True
    if changed:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: v.hex() for k, v in keys.items()}, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    return keys


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.kbs_server")
    ap.add_argument("--listen", default="127.0.0.1:8800", help="host:port (default 127.0.0.1:8800)")
    ap.add_argument("--policy", required=True, help="policy JSON (measurement allow-list, min TCB, ...)")
    ap.add_argument("--keys", default="kbs-keys.json", help="key store JSON {key_id: hex}; created if missing")
    ap.add_argument("--key-id", action="append", default=[], help="key ids to create if missing (default index-dek)")
    ap.add_argument("--product", choices=["Milan", "Genoa", "Turin"])
    ap.add_argument("--kds-cache", help="VCEK cache dir (default ~/.cache/attestrag/kds)")
    ap.add_argument("--nonce-ttl", type=float, default=60.0)
    args = ap.parse_args(argv)

    policy = Policy.from_json(Path(args.policy).read_text())
    keys = load_keys(Path(args.keys), tuple(args.key_id or ["index-dek"]))
    verifier = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(KdsClient(args.kds_cache), product=args.product)})
    kbs = ReferenceKBS(verifier, policy, nonce_ttl_s=args.nonce_ttl)
    for k, v in keys.items():
        kbs.put_key(k, v)

    routes = kbs_routes(kbs)
    inner = routes["/key"]

    def key_with_audit(req: dict) -> dict:
        try:
            return inner(req)
        finally:
            if kbs.audit:
                a = kbs.audit[-1]
                print(f"[kbs] key={a.key_id} allowed={a.allowed} measurement={(a.measurement or '')[:24]} "
                      f"reasons={list(a.reasons)}", file=sys.stderr, flush=True)
    routes["/key"] = key_with_audit

    host, port = args.listen.rsplit(":", 1)
    srv = JsonServer(routes, (host, int(port)))
    print(f"[kbs] listening on {srv.url}; keys={sorted(keys)}; policy={args.policy}; "
          f"allowed measurements={[m[:16] + '...' for m in sorted(policy.allowed_measurements)]}",
          file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
