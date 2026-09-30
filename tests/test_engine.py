import pytest

from ssrf_probe.engine import Engine, PLACEHOLDER, urllib_quote
from ssrf_probe.payloads import Payload


def make_engine(responses):
    """Build an Engine whose fetcher returns canned (status, body) by URL substring."""

    def fetcher(url, timeout):
        for needle, (status, body) in responses.items():
            if needle in url:
                return status, body
        return 200, ""

    return Engine(fetcher=fetcher, timeout=1.0)


def test_template_must_contain_placeholder():
    engine = make_engine({})
    p = Payload("http://127.0.0.1/", "loopback", "x")
    with pytest.raises(ValueError):
        engine.probe_one("http://host/fetch?url=nope", p)


def test_marker_match_raises_confidence():
    # Simulate the target echoing AWS metadata back to us.
    body = "ami-id\ninstance-id\niam/"
    engine = make_engine({"169.254.169.254": (200, body)})
    p = Payload(
        "http://169.254.169.254/latest/meta-data/",
        "cloud-metadata",
        "aws",
        ("ami-id", "instance-id"),
    )
    result = engine.probe_one(f"http://host/fetch?url={PLACEHOLDER}", p)
    assert result.status == 200
    assert set(result.matched_markers) == {"ami-id", "instance-id"}
    assert result.confidence == "likely"


def test_no_marker_is_inconclusive():
    engine = make_engine({"127.0.0.1": (200, "nothing interesting")})
    p = Payload("http://127.0.0.1/", "loopback", "x", ("SHOULD-NOT-APPEAR",))
    result = engine.probe_one(f"http://host/fetch?url={PLACEHOLDER}", p)
    assert result.confidence == "inconclusive"


def test_error_is_captured_not_raised():
    def boom(url, timeout):
        raise ConnectionRefusedError("nope")

    engine = Engine(fetcher=boom, timeout=1.0)
    p = Payload("http://127.0.0.1/", "loopback", "x")
    result = engine.probe_one(f"http://host/fetch?url={PLACEHOLDER}", p)
    assert result.error == "ConnectionRefusedError"
    assert result.confidence == "error"


def test_oob_payload_skipped_without_listener():
    engine = make_engine({})
    p = Payload("http://{token}/", "oob", "blind")
    result = engine.probe_one(f"http://host/fetch?url={PLACEHOLDER}", p)
    assert "skipped" in (result.error or "")


def test_run_returns_one_result_per_payload():
    engine = make_engine({})
    payloads = [
        Payload("http://127.0.0.1/", "loopback", "a"),
        Payload("http://localhost/", "loopback", "b"),
    ]
    results = engine.run(f"http://host/fetch?url={PLACEHOLDER}", payloads)
    assert len(results) == 2


def test_payload_is_url_encoded_in_target():
    captured = {}

    def fetcher(url, timeout):
        captured["url"] = url
        return 200, ""

    engine = Engine(fetcher=fetcher, timeout=1.0)
    p = Payload("http://127.0.0.1/a b", "loopback", "x")
    engine.probe_one(f"http://host/fetch?url={PLACEHOLDER}", p)
    # The space and slashes must be encoded so the outer request stays valid.
    assert "http%3A%2F%2F127.0.0.1%2Fa%20b" in captured["url"]


def test_urllib_quote_encodes_reserved():
    assert urllib_quote("a/b?c=d") == "a%2Fb%3Fc%3Dd"
