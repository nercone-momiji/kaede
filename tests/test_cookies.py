"""
Cookie conformance tests (RFC 6265).
"""
from __future__ import annotations

from datetime import datetime, timezone

from kaede.http.cookies import Cookie, parse_cookie_header, parse_set_cookie

class TestParseCookieHeader:
    def test_single(self):
        assert parse_cookie_header("a=1") == [("a", "1")]

    def test_multiple(self):
        assert parse_cookie_header("a=1; b=2") == [("a", "1"), ("b", "2")]

    def test_quoted_value(self):
        assert parse_cookie_header('a="hello"') == [("a", "hello")]

    def test_skips_malformed(self):
        assert parse_cookie_header("a=1; broken; b=2") == [("a", "1"), ("b", "2")]

class TestSerialize:
    def test_minimal(self):
        assert Cookie("sid", "abc").serialize() == "sid=abc"

    def test_full(self):
        c = Cookie(
            "sid", "abc",
            expires=datetime(1994, 11, 6, 8, 49, 37, tzinfo=timezone.utc),
            max_age=3600, domain="example.com", path="/", secure=True,
            http_only=True, same_site="Lax",
        )
        assert c.serialize() == (
            "sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Max-Age=3600; "
            "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax"
        )

    def test_rejects_bad_name(self):
        import pytest
        with pytest.raises(ValueError):
            Cookie("bad name", "v").serialize()

    def test_rejects_bad_value(self):
        import pytest
        with pytest.raises(ValueError):
            Cookie("n", "a;b").serialize()

class TestParseSetCookie:
    def test_basic(self):
        c = parse_set_cookie("sid=abc")
        assert c.name == "sid" and c.value == "abc"

    def test_attributes(self):
        c = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=60")
        assert c.path == "/"
        assert c.secure is True
        assert c.http_only is True
        assert c.same_site == "Strict"
        assert c.max_age == 60

    def test_expires_parsed(self):
        c = parse_set_cookie("sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT")
        assert c.expires == datetime(1994, 11, 6, 8, 49, 37, tzinfo=timezone.utc)

    def test_no_value_pair_returns_none(self):
        assert parse_set_cookie("nopair") is None

    def test_round_trip(self):
        original = "sid=abc; Max-Age=3600; Path=/; Secure"
        assert parse_set_cookie(original).serialize() == original
