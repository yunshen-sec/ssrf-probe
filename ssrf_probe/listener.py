"""Out-of-band (OAST) callback listener for confirming blind SSRF.

Blind SSRF gives you nothing in the HTTP response, so the only reliable proof is
a request arriving from the target at a host you control. This module runs a
small HTTP listener that records every inbound request together with the unique
token embedded in its Host header or path, so a hit can be attributed back to the
exact probe that caused it.

Run this on a machine the target can reach and point ``--oob-domain`` at it.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


@dataclass
class Callback:
    token: str
    method: str
    path: str
    host: str
    remote_ip: str
    user_agent: str
    received_at: float

    def as_dict(self) -> dict:
        return asdict(self)


def _extract_token(host_header: str, path: str) -> str:
    """Recover the probe token from the Host header or the request path.

    OOB payloads look like ``http://<token>.<oob-domain>/`` or
    ``http://<oob-domain>/<token>``; either form is supported.
    """
    if host_header:
        label = host_header.split(":", 1)[0].split(".", 1)[0]
        if label:
            return label
    return path.strip("/").split("/", 1)[0]


class CallbackListener:
    """A threaded HTTP listener that captures SSRF callbacks."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        self.host = host
        self.port = port
        self._callbacks: list[Callback] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- capture API -----------------------------------------------------
    def _record(self, cb: Callback) -> None:
        with self._lock:
            self._callbacks.append(cb)

    def callbacks(self) -> list[Callback]:
        with self._lock:
            return list(self._callbacks)

    def seen_token(self, token: str) -> bool:
        with self._lock:
            return any(cb.token == token for cb in self._callbacks)

    def wait_for(self, token: str, timeout: float = 10.0) -> Callback | None:
        """Block until a callback for ``token`` arrives or ``timeout`` elapses."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for cb in self._callbacks:
                    if cb.token == token:
                        return cb
            time.sleep(0.05)
        return None

    # -- lifecycle -------------------------------------------------------
    def _handler_factory(self) -> Callable[..., BaseHTTPRequestHandler]:
        listener = self

        class Handler(BaseHTTPRequestHandler):
            # Silence the default stderr logging; we keep our own records.
            def log_message(self, *_args) -> None:  # noqa: D401,N802
                return

            def _capture(self) -> None:
                host_header = self.headers.get("Host", "")
                token = _extract_token(host_header, self.path)
                listener._record(
                    Callback(
                        token=token,
                        method=self.command,
                        path=self.path,
                        host=host_header,
                        remote_ip=self.client_address[0],
                        user_agent=self.headers.get("User-Agent", ""),
                        received_at=time.time(),
                    )
                )
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            # Answer every verb the same way.
            do_GET = _capture  # noqa: N815
            do_POST = _capture  # noqa: N815
            do_PUT = _capture  # noqa: N815
            do_HEAD = _capture  # noqa: N815

        return Handler

    def start(self) -> "CallbackListener":
        if self._server is not None:
            raise RuntimeError("listener already started")
        self._server = ThreadingHTTPServer((self.host, self.port), self._handler_factory())
        # Bind may have picked an ephemeral port when port==0.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "CallbackListener":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def dump(self) -> str:
        return json.dumps([cb.as_dict() for cb in self.callbacks()], indent=2)
