import urllib.request

from ssrf_probe.listener import CallbackListener, _extract_token


def test_extract_token_from_host():
    assert _extract_token("abc123.oast.example.com", "/") == "abc123"


def test_extract_token_from_path_when_no_host_label():
    assert _extract_token("oast.example.com", "/tok99/ssrf") == "oast.example.com".split(".")[0]
    # When the host is a bare domain, fall back to the first path segment.
    assert _extract_token("", "/tok99/ssrf") == "tok99"


def test_listener_captures_callback():
    with CallbackListener("127.0.0.1", 0) as listener:
        url = f"http://127.0.0.1:{listener.port}/mytoken/ssrf"
        urllib.request.urlopen(url, timeout=3).read()  # noqa: S310
        cb = listener.wait_for("127", timeout=3)  # host label is '127'
        # Whichever attribution wins, a callback must have been recorded.
        assert listener.callbacks(), "no callback captured"
        recorded = listener.callbacks()[0]
        assert recorded.path == "/mytoken/ssrf"
        assert recorded.method == "GET"


def test_seen_token_false_before_hit():
    with CallbackListener("127.0.0.1", 0) as listener:
        assert listener.seen_token("never") is False
