"""Command-line interface for ssrf-probe.

Example (against a lab target you are authorized to test):

    ssrf-probe \\
        --template 'http://target.local/fetch?url=FUZZ' \\
        --authorized \\
        --oob-domain oast.example.com --listen 0.0.0.0:8080
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .engine import Engine, PLACEHOLDER
from .listener import CallbackListener
from .payloads import all_payloads

AUTHORIZATION_NOTICE = (
    "ssrf-probe sends crafted requests to a target. Only run it against systems "
    "you own or have explicit written permission to test. Re-run with --authorized "
    "to confirm you have that permission."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ssrf-probe",
        description="Authorized SSRF testing toolkit.",
    )
    p.add_argument(
        "--template",
        required=True,
        help=f"Target request with the {PLACEHOLDER!r} placeholder where a URL is fetched, "
        f"e.g. 'http://host/fetch?url={PLACEHOLDER}'",
    )
    p.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you are permitted to test this target (required).",
    )
    p.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout (s).")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests (s).")
    p.add_argument("--no-metadata", action="store_true", help="Skip cloud-metadata payloads.")
    p.add_argument("--no-schemes", action="store_true", help="Skip non-HTTP scheme payloads.")
    p.add_argument(
        "--oob-domain",
        help="Base domain of your callback listener for blind-SSRF probes.",
    )
    p.add_argument(
        "--listen",
        help="Start a local callback listener at HOST:PORT (use with --oob-domain).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.authorized:
        print(AUTHORIZATION_NOTICE, file=sys.stderr)
        return 2

    if PLACEHOLDER not in args.template:
        print(f"error: --template must contain {PLACEHOLDER!r}", file=sys.stderr)
        return 2

    listener: CallbackListener | None = None
    if args.listen:
        host, _, port = args.listen.partition(":")
        listener = CallbackListener(host or "0.0.0.0", int(port or 8080)).start()
        print(f"[*] callback listener on {listener.host}:{listener.port}", file=sys.stderr)

    payloads = all_payloads(
        include_metadata=not args.no_metadata,
        include_schemes=not args.no_schemes,
        include_oob=bool(args.oob_domain),
        oob_domain=args.oob_domain,
    )

    engine = Engine(
        listener=listener,
        oob_domain=args.oob_domain,
        timeout=args.timeout,
        delay=args.delay,
    )

    print(f"[*] {len(payloads)} payloads against: {args.template}", file=sys.stderr)
    findings = 0
    try:
        for result in engine.run(args.template, payloads):
            line = result.summary()
            if result.confidence in {"confirmed", "likely"}:
                findings += 1
                print(f">> {line}")
            else:
                print(f"   {line}")
    finally:
        if listener is not None:
            listener.stop()

    print(f"[*] done: {findings} result(s) worth verifying", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
