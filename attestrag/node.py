"""The TEE-resident AttestRAG node: everything in here runs inside the CVM.

Boot:   prove to KBS -> receive, per tenant, the index DEK with its committed version and
        the tenant's client token (release signed by the pinned KBS) -> open that tenant's
        sealed index, refusing anything older than the committed version.
Serve:  attestation(nonce) for clients; ingest/query over payloads encrypted to the node's
        transport key, whose public half is bound into every report. Every request names a
        tenant and, when the tenant has a token, carries an HMAC under it over the encrypted
        payload: only that tenant's clients reach that tenant's index. After an ingest the
        node seals the index as version v+1 and commits v+1 to the KBS.
        The answer is sealed with a one-time key the client sent inside the encrypted
        question, so only the node that could decrypt the question (i.e. the attested one)
        can produce an answer the client accepts.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .attest.base import CompositeAttester
from .attest.types import CompositeEvidence
from .common.crypto import WrappedKey, mac, mac_ok, seal, unwrap, x25519_public_bytes
from .embed import Embedder
from .generate import Answer, Generator
from .index import EncryptedVectorIndex, VectorStore
from .ingest import chunk_text, parse
from .kbs_client import KBSClient, VersionCommitRejected
from .retrieve import Retriever

INGEST_INFO = b"attestrag-ingest-v2|"   # + tenant|doc_id
QUERY_INFO = b"attestrag-query-v2|"     # + tenant
ANSWER_INFO = b"attestrag-answer-v1"
TENANT_AUTH_LABEL = b"attestrag-tenant-auth-v1"
DEFAULT_TENANT = "index-dek"


GATE_TEXT = ("The retrieved context is insufficient to answer this question: no relevant passage was found. "
             "检索到的上下文不足以回答该问题，语料中没有相关依据，无法作答。")


def ingest_info(tenant: str, doc_id: str) -> bytes:
    return INGEST_INFO + tenant.encode() + b"|" + doc_id.encode()


def query_info(tenant: str) -> bytes:
    return QUERY_INFO + tenant.encode()


def tenant_auth(token: bytes, purpose: bytes, tenant: str, wrapped: WrappedKey) -> bytes:
    """Client-side tag over the encrypted request: proves the sender holds the tenant's token and binds
    the tenant name to this very ciphertext (a host cannot re-route a request to another tenant's index)."""
    return mac(token, TENANT_AUTH_LABEL, purpose, tenant.encode(), wrapped.eph_pub, wrapped.ciphertext)


class TenantAuthError(PermissionError):
    pass


class UnknownTenant(KeyError):
    pass


@dataclass
class Tenant:
    id: str
    dek: bytes
    token: bytes | None
    version: int      # version of the state in memory and on disk
    committed: int    # last version the KBS acknowledged
    store: VectorStore
    path: Path


class AttestRAGNode:
    def __init__(
        self,
        attester: CompositeAttester,
        kbs: KBSClient,
        embedder: Embedder,
        generator: Generator,
        data_dir: str | Path,
        index_key_id: str = DEFAULT_TENANT,
        store: VectorStore | None = None,
        min_score: float = 0.0,
        judge: bool = False,
        tenants: Sequence[str] | None = None,
        store_factory: Callable[[str], VectorStore] | None = None,
    ):
        # relevance gate, two stages, both part of the measured node configuration (node.env):
        #  1. score: the best retrieved chunk must score at least min_score (0 = off; cheap, but embedding
        #     similarity measures topic, not answer presence, see scripts/gate_calibrate.py);
        #  2. judge: the generator answers YES/NO to "does the context contain the answer" before it is
        #     asked to answer (one short completion; the verifier pass).
        # A refused question gets GATE_TEXT and the generator is never asked for an answer.
        self.min_score = float(min_score)
        self.judge = bool(judge)
        self.attester = attester
        self.kbs = kbs
        self.embedder = embedder
        self.generator = generator
        self.data_dir = Path(data_dir)
        # tenants: one KBS key id each, one sealed index each. The default is the single tenant index_key_id
        # with the historical file names; explicit tenants get per-tenant file names.
        self.tenant_ids: tuple[str, ...] = tuple(tenants) if tenants else (index_key_id,)
        self._explicit_tenants = bool(tenants)
        self._store = store
        self._store_factory = store_factory
        self._transport = X25519PrivateKey.generate()
        self.transport_pub = x25519_public_bytes(self._transport.public_key())
        self.tenants: dict[str, Tenant] = {}

    # --- compatibility views on the first tenant --------------------------
    @property
    def index_key_id(self) -> str:
        return self.tenant_ids[0]

    @property
    def index(self) -> VectorStore | None:
        t = self.tenants.get(self.tenant_ids[0])
        return t.store if t else None

    @property
    def index_path(self) -> Path:
        t = self.tenants.get(self.tenant_ids[0])
        return t.path if t else self.data_dir / self._make_store(self.tenant_ids[0]).filename

    def _make_store(self, tenant: str) -> VectorStore:
        if self._store_factory is not None:
            return self._store_factory(tenant)
        if self._store is not None:   # no `or`: it would call __len__
            if len(self.tenant_ids) > 1:
                raise RuntimeError("one store object cannot serve several tenants; pass store_factory")
            return self._store
        return EncryptedVectorIndex(self.embedder.dim, filename=f"index-{tenant}.enc" if self._explicit_tenants else None)

    def start(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for tid in self.tenant_ids:
            rel = self.kbs.get_release(tid)  # raises KeyReleaseDenied / AttestationError (bad KBS signature)
            store = self._make_store(tid)
            if store.dim != self.embedder.dim:
                raise RuntimeError(f"vector store dim {store.dim} != embedder dim {self.embedder.dim}")
            path = self.data_dir / store.filename
            found = store.open(path, rel.key, min_version=rel.version)   # IndexRollback when older than committed
            t = Tenant(tid, rel.key, rel.token, max(found, rel.version), rel.version, store, path)
            self.tenants[tid] = t
            if found > rel.version:   # sealed after the last commit the KBS saw: catch the KBS up
                self._commit(t)

    def _commit(self, t: Tenant) -> None:
        try:
            t.committed = self.kbs.commit_version(t.id, t.version, t.dek)
        except VersionCommitRejected:
            raise   # another holder of this key advanced it, or the KBS was reset: not ours to paper over
        except Exception as e:  # noqa: BLE001  KBS unreachable: the state is sealed on disk, re-committed at the next start
            print(f"[node] version commit {t.id} v{t.version} failed, retried at next ingest/start: {e}", file=sys.stderr)

    def _tenant(self, tenant: str | None) -> Tenant:
        if not self.tenants:
            raise RuntimeError("node not started (key not released)")
        tid = tenant or self.tenant_ids[0]
        t = self.tenants.get(tid)
        if t is None:
            raise UnknownTenant(tid)
        return t

    @staticmethod
    def _authenticate(t: Tenant, purpose: bytes, wrapped: WrappedKey, auth: bytes | None) -> None:
        if t.token is None:
            return
        if auth is None or not mac_ok(t.token, auth, TENANT_AUTH_LABEL, purpose, t.id.encode(), wrapped.eph_pub, wrapped.ciphertext):
            raise TenantAuthError(f"tenant {t.id!r}: request not authenticated with the tenant token")

    # --- client-facing API -------------------------------------------------
    def attestation(self, nonce: bytes) -> tuple[CompositeEvidence, bytes]:
        return self.attester.attest_for(nonce, self.transport_pub), self.transport_pub

    def ingest(self, doc_id: str, wrapped: WrappedKey, content_type: str = "text/plain",
               tenant: str | None = None, auth: bytes | None = None) -> int:
        t = self._tenant(tenant)
        self._authenticate(t, b"ingest", wrapped, auth)
        data = unwrap(self._transport, wrapped, info=ingest_info(t.id, doc_id))
        chunks = chunk_text(doc_id, parse(data, content_type))
        if not chunks:
            return 0
        vecs = self.embedder.embed([c.text for c in chunks])
        t.store.add(vecs, [{"chunk_id": c.id, "doc_id": c.doc_id, "text": c.text, **c.meta} for c in chunks])
        t.version += 1
        t.store.save(t.path, t.dek, t.version)
        self._commit(t)
        return len(chunks)

    def query(self, wrapped_question: WrappedKey, k: int = 4, tenant: str | None = None,
              auth: bytes | None = None) -> bytes:
        """wrapped_question = wrap_to(node_pub, {"question", "reply_key"}); returns seal(reply_key, answer)."""
        t = self._tenant(tenant)
        self._authenticate(t, b"query", wrapped_question, auth)
        req = json.loads(unwrap(self._transport, wrapped_question, info=query_info(t.id)))
        question, reply_key = req["question"], bytes.fromhex(req["reply_key"])
        hits = Retriever(self.embedder, t.store).retrieve(question, k)
        top = hits[0].score if hits else 0.0
        why = None
        if self.min_score > 0 and top < self.min_score:
            why = "score"
        elif self.judge and not self.generator.judge(question, hits):
            why = "judge"
        answer = Answer(GATE_TEXT, (), "gate") if why else self.generator.generate(question, hits)
        payload = json.dumps({"answer": asdict(answer), "hits": [asdict(h) for h in hits],
                              "gate": {"min_score": self.min_score, "judge": self.judge, "top_score": top,
                                       "rejected": why is not None, "reason": why},
                              "tenant": t.id, "index_version": t.version}).encode()
        return seal(reply_key, payload, aad=ANSWER_INFO)


def node_routes(node: AttestRAGNode) -> dict:
    """HTTP routes for AttestRAGNode (see transport.JsonServer)."""
    from .transport import HttpError, evidence_to_dict, wrapped_from_dict

    def guard(fn):
        def wrapped(req: dict) -> dict:
            try:
                return fn(req)
            except TenantAuthError as e:
                raise HttpError(403, "tenant authentication failed", (str(e),)) from None
            except UnknownTenant as e:
                raise HttpError(404, f"unknown tenant {e.args[0]!r}") from None
        return wrapped

    def attestation(req: dict) -> dict:
        ev, pub = node.attestation(bytes.fromhex(req["nonce"]))
        return {"evidence": evidence_to_dict(ev), "node_pub": pub.hex()}

    def auth_of(req: dict) -> bytes | None:
        return bytes.fromhex(req["auth"]) if req.get("auth") else None

    @guard
    def ingest(req: dict) -> dict:
        tenant = req.get("tenant")
        n = node.ingest(req["doc_id"], wrapped_from_dict(req["wrapped"]), req.get("content_type", "text/plain"),
                        tenant=tenant, auth=auth_of(req))
        t = node._tenant(tenant)
        return {"chunks": n, "version": t.version, "committed": t.committed == t.version}

    @guard
    def query(req: dict) -> dict:
        return {"sealed": node.query(wrapped_from_dict(req["wrapped"]), int(req.get("k", 4)),
                                     tenant=req.get("tenant"), auth=auth_of(req)).hex()}

    return {"/attestation": attestation, "/ingest": ingest, "/query": query}
