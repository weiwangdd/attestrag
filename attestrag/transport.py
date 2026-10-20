"""Wire format and a minimal HTTP layer (stdlib only).

Everything secret on the wire is already encrypted to an attested key (see
node.py / kbs_client); HTTP here carries JSON with hex-encoded bytes and needs
no TLS for confidentiality. A deployment may still put TLS in front for
privacy of metadata and to resist tampering with error paths.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .attest.types import CompositeEvidence, Evidence
from .common.crypto import WrappedKey

MAX_BODY = 64 * 1024 * 1024
Handler = Callable[[dict], dict]


class HttpError(Exception):
    def __init__(self, status: int, error: str, reasons: tuple[str, ...] = ()):
        super().__init__(error if not reasons else f"{error}: " + "; ".join(reasons))
        self.status, self.error, self.reasons = status, error, reasons


# --------------------------------------------------------------------------- codecs

def evidence_to_dict(ev: CompositeEvidence) -> dict:
    return {"cpu": json.loads(ev.cpu.to_json()), "gpus": [json.loads(g.to_json()) for g in ev.gpus]}


def evidence_from_dict(d: dict) -> CompositeEvidence:
    return CompositeEvidence(Evidence.from_json(json.dumps(d["cpu"])),
                             tuple(Evidence.from_json(json.dumps(g)) for g in d.get("gpus", [])))


def wrapped_to_dict(w: WrappedKey) -> dict:
    return {"eph_pub": w.eph_pub.hex(), "ciphertext": w.ciphertext.hex()}


def wrapped_from_dict(d: dict) -> WrappedKey:
    return WrappedKey(bytes.fromhex(d["eph_pub"]), bytes.fromhex(d["ciphertext"]))


# --------------------------------------------------------------------------- server

class JsonServer:
    """POST-only JSON RPC over HTTP: one handler per path, dict in -> dict out."""

    def __init__(self, routes: dict[str, Handler], listen: tuple[str, int] = ("127.0.0.1", 0),
                 on_error: Callable[[Exception], HttpError | None] | None = None, quiet: bool = True):
        self.routes = routes
        self.on_error = on_error
        srv = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # noqa: D401
                if not quiet:
                    super().log_message(*a)

            def _send(self, status: int, obj: dict):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/healthz":
                    return self._send(200, {"ok": True})
                self._send(404, {"error": "not found"})

            def do_POST(self):
                fn = srv.routes.get(self.path)
                if fn is None:
                    return self._send(404, {"error": "not found"})
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                    if n > MAX_BODY:
                        return self._send(413, {"error": "body too large"})
                    req = json.loads(self.rfile.read(n) or b"{}")
                    if not isinstance(req, dict):
                        raise ValueError("JSON object expected")
                    self._send(200, fn(req))
                except HttpError as e:
                    self._send(e.status, {"error": e.error, "reasons": list(e.reasons)})
                except (ValueError, KeyError, TypeError) as e:
                    self._send(400, {"error": f"bad request: {e}"})
                except Exception as e:  # noqa: BLE001
                    he = srv.on_error(e) if srv.on_error else None
                    if he is None:
                        he = HttpError(500, f"{type(e).__name__}: {e}")
                    self._send(he.status, {"error": he.error, "reasons": list(he.reasons)})

        self.httpd = ThreadingHTTPServer(listen, H)
        self.httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "JsonServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------------- client

def post_json(url: str, obj: dict, timeout: float = 60.0) -> dict:
    body = json.dumps(obj).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            d = json.load(e)
        except ValueError:
            d = {"error": e.reason}
        raise HttpError(e.code, d.get("error", "error"), tuple(d.get("reasons", []))) from None
    except OSError as e:
        raise HttpError(0, f"{url} unreachable: {e}") from None
