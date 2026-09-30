from ssrf_probe.payloads import (
    Payload,
    all_payloads,
    categories,
    filter_by_category,
)


def test_default_set_has_loopback_and_metadata():
    payloads = all_payloads()
    cats = {p.category for p in payloads}
    assert "loopback" in cats
    assert "cloud-metadata" in cats


def test_metadata_can_be_excluded():
    payloads = all_payloads(include_metadata=False)
    assert all(p.category != "cloud-metadata" for p in payloads)


def test_oob_only_included_with_domain():
    without = all_payloads(include_oob=True, oob_domain=None)
    assert all(not p.is_oob for p in without)
    with_domain = all_payloads(include_oob=True, oob_domain="oast.example.com")
    assert any(p.is_oob for p in with_domain)


def test_loopback_encodings_present():
    values = {p.value for p in all_payloads()}
    # The integer and hex encodings are the ones that slip past naive checks.
    assert "http://2130706433/" in values
    assert "http://0x7f.0x0.0x0.0x1/" in values
    assert "http://[::1]/" in values


def test_rendered_substitutes_token():
    p = Payload("http://{token}/", "oob", "blind")
    assert p.is_oob
    assert p.rendered("abc.oast.example.com") == "http://abc.oast.example.com/"


def test_rendered_without_token_is_verbatim():
    p = Payload("http://127.0.0.1/", "loopback", "x")
    assert not p.is_oob
    assert p.rendered() == "http://127.0.0.1/"


def test_filter_by_category():
    payloads = all_payloads()
    meta = filter_by_category(payloads, "cloud-metadata")
    assert meta
    assert all(p.category == "cloud-metadata" for p in meta)


def test_categories_helper():
    assert "loopback" in categories()
    assert "scheme" in categories()
