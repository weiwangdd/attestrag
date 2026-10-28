"""Key Broker Service over HTTP. Runs OUTSIDE the CVM, in the data owner's trust domain.

    python -m attestrag.kbs_server --policy policies/h200-genoa.json --keys kbs-keys.json

Releases a key only to a TEE whose SEV-SNP evidence verifies and passes the policy;
the key is wrapped to the X25519 public key bound into the attestation report and the
release is signed with the KBS identity (print it with --print-pubkey; the node pins it
with --kbs-pubkey). The key store also holds, per key id (= tenant), the committed index
version and the tenant's client token.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .attest import CompositeVerifier, Platform
from .attest.snp import KdsClient, SnpVerifier
from .attest.nvidia import NvidiaVerifier
from .common.crypto import new_key
from .kbs_client import KeyRecord, ReferenceKBS, kbs_routes
from .kbs_client.reference_kbs import identity_public_bytes
from .policy import Policy
from .transport import JsonServer

FORMAT = "attestrag-kbs-keys-v2"


class KeyStore:
    """{"format", "identity": hex seed, "keys": {id: {"key", "version", "token"}}}; a flat {id: hex} file
    from before versioning is migrated on load. Written atomically, mode 0600."""

    def __init__(self, path: Path):
        self.path = path
        self.identity: Ed25519PrivateKey
        self.records: dict[str, KeyRecord] = {}
        self.changed = False
        if path.exists():
            d = json.loads(path.read_text())
            if d.get("format") == FORMAT:
                self.identity = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["identity"]))
                for k, r in d["keys"].items():
                    self.records[k] = KeyRecord(bytes.fromhex(r["key"]), int(r.get("version", 0)),
                                                bytes.fromhex(r["token"]) if r.get("token") else None)
            else:   # legacy flat store: keys only
                self.identity = Ed25519PrivateKey.generate()
                self.records = {k: KeyRecord(bytes.fromhex(v)) for k, v in d.items()}
                self.changed = True
        else:
            self.identity = Ed25519PrivateKey.generate()
            self.changed = True

    def ensure(self, key_id: str, token: bool = False) -> KeyRecord:
        rec = self.records.get(key_id)
        if rec is None:
            rec = self.records[key_id] = KeyRecord(new_key())
            self.changed = True
        if token and rec.token is None:
            rec.token = new_key()
            self.changed = True
        return rec

    def token_path(self, key_id: str) -> Path:
        return self.path.with_name(f"{self.path.stem}.{key_id}.token")

    def save(self, records: dict[str, KeyRecord] | None = None) -> None:
        if records is not None:
            self.records = records
        d = {"format": FORMAT, "identity": self.identity.private_bytes_raw().hex(),
             "keys": {k: {"key": r.key.hex(), "version": r.version, **({"token": r.token.hex()} if r.token else {})}
                      for k, r in self.records.items()}}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        self.changed = False


def nvidia_verifier(args) -> NvidiaVerifier:
    if not getattr(args, "gpu_rim", False):
        return NvidiaVerifier()
    from .attest.nvidia_rim import OcspClient, RimClient
    base = Path(args.nvidia_cache) if args.nvidia_cache else Path.home() / ".cache" / "attestrag" / "nvidia"
    return NvidiaVerifier(rim=RimClient(base / "rim"), ocsp=OcspClient(cache_dir=base / "ocsp"))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m attestrag.kbs_server")
    ap.add_argument("--listen", default="127.0.0.1:8800", help="host:port (default 127.0.0.1:8800)")
    ap.add_argument("--policy", help="policy JSON (measurement allow-list, min TCB, ...); required to serve")
    ap.add_argument("--keys", default="kbs-keys.json", help="key store JSON; created if missing")
    ap.add_argument("--key-id", action="append", default=[], help="key ids to create if missing (default index-dek)")
    ap.add_argument("--tenant", action="append", default=[], metavar="ID",
                    help="tenant to create if missing: key id ID with a client token, written next to the key store "
                         "as <keys>.ID.token (0600); hand it to that tenant's clients (--token-file)")
    ap.add_argument("--reset-version", action="append", default=[], metavar="ID",
                    help="operator decision after a legitimate loss of the index: set ID's committed version back to 0")
    ap.add_argument("--print-pubkey", action="store_true", help="print the KBS identity public key (hex) and exit")
    ap.add_argument("--product", choices=["Milan", "Genoa", "Turin"])
    ap.add_argument("--kds-cache", help="VCEK cache dir (default ~/.cache/attestrag/kds)")
    ap.add_argument("--nonce-ttl", type=float, default=60.0)
    ap.add_argument("--gpu-rim", action="store_true",
                    help="also check GPU evidence against NVIDIA's reference manifests (RIM service) and OCSP; cached in --nvidia-cache")
    ap.add_argument("--nvidia-cache", help="cache dir for RIMs and OCSP responses (default ~/.cache/attestrag/nvidia)")
    ap.add_argument("--insecure-mock", action="store_true",
                    help="also trust the public insecure-baseline mock vendor (unprotected baseline only; proves nothing)")
    args = ap.parse_args(argv)

    store = KeyStore(Path(args.keys))
    for k in args.key_id or ["index-dek"]:
        store.ensure(k)
    for t in args.tenant:
        new = t not in store.records or store.records[t].token is None
        store.ensure(t, token=True)
        if new:
            p = store.token_path(t)
            p.write_text(store.records[t].token.hex() + "\n")
            os.chmod(p, 0o600)
            print(f"[kbs] tenant {t!r}: new client token written to {p}", file=sys.stderr)
    for k in args.reset_version:
        store.ensure(k).version = 0
        store.changed = True
        print(f"[kbs] WARNING: committed index version of {k!r} reset to 0 by the operator", file=sys.stderr)
    if store.changed:
        store.save()
    pub = identity_public_bytes(store.identity).hex()
    if args.print_pubkey:
        print(pub)
        return
    if not args.policy:
        ap.error("--policy is required to serve")

    policy = Policy.from_json(Path(args.policy).read_text())
    verifier = CompositeVerifier({Platform.SEV_SNP: SnpVerifier(KdsClient(args.kds_cache), product=args.product),
                                   Platform.NVIDIA_CC: nvidia_verifier(args)})
    if args.insecure_mock:
        from .attest.mock import insecure_baseline_verifier
        print("WARNING: --insecure-mock: accepting evidence from the public mock vendor; nothing is protected", file=sys.stderr)
        verifier = CompositeVerifier({**verifier.verifiers, Platform.MOCK_CPU: insecure_baseline_verifier()})
    kbs = ReferenceKBS(verifier, policy, nonce_ttl_s=args.nonce_ttl, identity=store.identity, on_change=store.save)
    for k, r in store.records.items():
        kbs.put_key(k, r.key, r.version, r.token)

    routes = kbs_routes(kbs)
    inner_key, inner_commit = routes["/key"], routes["/commit"]

    def key_with_audit(req: dict) -> dict:
        try:
            return inner_key(req)
        finally:
            if kbs.audit:
                a = kbs.audit[-1]
                print(f"[kbs] key={a.key_id} allowed={a.allowed} measurement={(a.measurement or '')[:24]} "
                      f"reasons={list(a.reasons)}", file=sys.stderr, flush=True)

    def commit_with_log(req: dict) -> dict:
        try:
            d = inner_commit(req)
            print(f"[kbs] commit key={req.get('key_id')} version={d['version']}", file=sys.stderr, flush=True)
            return d
        except Exception as e:  # noqa: BLE001
            print(f"[kbs] commit key={req.get('key_id')} version={req.get('version')} REJECTED: {e}", file=sys.stderr, flush=True)
            raise
    routes["/key"], routes["/commit"] = key_with_audit, commit_with_log

    host, port = args.listen.rsplit(":", 1)
    srv = JsonServer(routes, (host, int(port)))
    print(f"[kbs] listening on {srv.url}; identity={pub}; keys={ {k: f'v{r.version}' + ('+token' if r.token else '') for k, r in store.records.items()} }; "
          f"policy={args.policy}; allowed measurements={[m[:16] + '...' for m in sorted(policy.allowed_measurements)]}",
          file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
