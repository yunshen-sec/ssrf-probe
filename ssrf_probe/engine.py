"""The probing engine: inject payloads, observe responses and callbacks, score.

The engine takes a *request template* that marks where a URL/host is fetched by
the target (with the literal ``FUZZ`` placeholder), substitutes each payload, and
records what happened. It never decides on its own that something is exploitable;
it reports evidence (status code, timing, response markers, out-of-band hits) and
a coarse confidence so a human can verify.
"""

from __future__ import annotations

import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from .payloads import Payload
from .listener import CallbackListener

PLACEHOLDER = "FUZZ"


@dataclass
class ProbeResult:
    payload: Payload
    url: str
    status: Optional[int] = None
    elapsed: float = 0.0
    error: Optional[str] = None
    matched_markers: tuple[str, ...] = field(default_factory=tuple)
    oob_confirmed: bool = False

    @property
    def confidence(self) -> str:
        """A coarse triage label. OOB confirmation is the only near-certain one."""
        if self.oob_confirmed:
            return "confirmed"
        if self.matched_markers:
            return "likely"
        if self.error:
            return "error"
        if self.status is not None:
            return "inconclusive"
        return "no-response"

    def summary(self) -> str:
        bits = [f"[{self.confidence}]", self.payload.category, self.payload.rendered()]
        if self.status is not None:
            bits.append(f"HTTP {self.status}")
        if self.matched_markers:
            bits.append("markers=" + ",".join(self.matched_markers))
        if self.oob_confirmed:
            bits.append("OOB-HIT")
        if self.error:
            bits.append(f"err={self.error}")
        return " ".join(bits)


# A fetcher takes a URL and returns (status, body_text). Injected so tests can
# run without network access and so callers can swap in their own HTTP client.
Fetcher = Callable[[str, float], tuple[int, str]]


def _default_fetcher(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "ssrf-probe/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read(65536)
        return resp.status, raw.decode("utf-8", "replace")


class Engine:
    def __init__(
        self,
        *,
        fetcher: Fetcher | None = None,
        listener: CallbackListener | None = None,
        oob_domain: str | None = None,
        timeout: float = 8.0,
        delay: float = 0.0,
    ) -> None:
        self.fetcher = fetcher or _default_fetcher
        self.listener = listener
        self.oob_domain = oob_domain
        self.timeout = timeout
        # A courtesy delay between requests; keep authorized targets happy and
        # avoid hammering internal services.
        self.delay = delay

    def _target_url(self, template: str, payload_value: str) -> str:
        if PLACEHOLDER not in template:
            raise ValueError(f"template must contain the {PLACEHOLDER!r} placeholder")
        return template.replace(PLACEHOLDER, urllib_quote(payload_value))

    def probe_one(self, template: str, payload: Payload) -> ProbeResult:
        token = None
        rendered = payload.value
        if payload.is_oob:
            if not (self.listener and self.oob_domain):
                # Can't run a blind probe without somewhere to hear the callback.
                return ProbeResult(
                    payload=payload,
                    url="",
                    error="oob payload skipped: no listener/oob_domain configured",
                )
            token = secrets.token_hex(8)
            rendered = payload.value.replace("{token}", f"{token}.{self.oob_domain}")

        url = self._target_url(template, rendered)
        result = ProbeResult(payload=payload, url=url)

        start = time.monotonic()
        try:
            status, body = self.fetcher(url, self.timeout)
            result.status = status
            result.matched_markers = tuple(
                m for m in payload.response_markers if m in body
            )
        except urllib.error.HTTPError as exc:  # noqa: PERF203
            result.status = exc.code
        except Exception as exc:  # noqa: BLE001 - report, never crash a run
            result.error = type(exc).__name__
        result.elapsed = time.monotonic() - start

        if token is not None and self.listener is not None:
            # Give the target a moment to make the outbound request.
            cb = self.listener.wait_for(token, timeout=min(self.timeout, 10.0))
            result.oob_confirmed = cb is not None

        return result

    def run(self, template: str, payloads: list[Payload]) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        for i, payload in enumerate(payloads):
            results.append(self.probe_one(template, payload))
            if self.delay and i < len(payloads) - 1:
                time.sleep(self.delay)
        return results


def urllib_quote(value: str) -> str:
    """URL-encode a payload for safe substitution into a query parameter.

    Kept as a thin wrapper so the encoding is consistent and easy to test.
    """
    from urllib.parse import quote

    return quote(value, safe="")
