"""
URL class conformance tests.

RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax
RFC 9110 §7.1 — Determining the Target Resource / request-target forms
RFC 9110 §7.2 — Host and :authority
"""
from __future__ import annotations

import ipaddress

import pytest

from kaede.http.url import URL
from kaede.http.models import Request, Headers


# ---------------------------------------------------------------------------
# URL.parse_authority helper
# ---------------------------------------------------------------------------

class TestURLParseAuthority:
    def test_empty_string(self):
        assert URL.parse_authority("") == ("", None)

    def test_host_only(self):
        assert URL.parse_authority("example.com") == ("example.com", None)

    def test_host_with_port(self):
        assert URL.parse_authority("example.com:8080") == ("example.com", 8080)

    def test_host_with_default_http_port(self):
        assert URL.parse_authority("example.com:80") == ("example.com", 80)

    def test_host_with_default_https_port(self):
        assert URL.parse_authority("example.com:443") == ("example.com", 443)

    def test_ipv4_only(self):
        assert URL.parse_authority("192.168.1.1") == ("192.168.1.1", None)

    def test_ipv4_with_port(self):
        assert URL.parse_authority("192.168.1.1:9000") == ("192.168.1.1", 9000)

    def test_ipv6_literal_only(self):
        assert URL.parse_authority("[::1]") == ("[::1]", None)

    def test_ipv6_literal_with_port(self):
        assert URL.parse_authority("[::1]:8080") == ("[::1]", 8080)

    def test_ipv6_full_address_with_port(self):
        assert URL.parse_authority("[2001:db8::1]:443") == ("[2001:db8::1]", 443)

    def test_invalid_port_treated_as_hostname(self):
        host, port = URL.parse_authority("example.com:notaport")
        assert port is None

    def test_port_zero(self):
        """Port 0 is a valid port number per RFC 3986."""
        assert URL.parse_authority("example.com:0") == ("example.com", 0)


# ---------------------------------------------------------------------------
# URL.from_target — origin-form (RFC 9110 §7.1, RFC 3986 §3)
# ---------------------------------------------------------------------------

class TestURLOriginForm:
    """RFC 9110 §7.1: origin-form is /abs-path [?query]."""

    def test_root_path(self):
        url = URL.from_target("/", "https", "example.com")
        assert url.path == "/"
        assert url.query == ""
        assert url.fragment == ""
        assert url.host == "example.com"
        assert url.scheme == "https"

    def test_path_with_segments(self):
        url = URL.from_target("/a/b/c", "http", "example.com")
        assert url.path == "/a/b/c"

    def test_path_with_query(self):
        url = URL.from_target("/search?q=hello", "http", "example.com")
        assert url.path == "/search"
        assert url.query == "q=hello"

    def test_path_with_fragment_rejected(self):
        """RFC 9112 §3.2: request targets MUST NOT contain fragment identifiers."""
        with pytest.raises(ValueError):
            URL.from_target("/page?a=1#section", "https", "example.com")

    def test_host_from_authority_with_port(self):
        url = URL.from_target("/api/v1", "https", "api.example.com:8443")
        assert url.host == "api.example.com"
        assert url.port == 8443

    def test_host_from_authority_no_port(self):
        url = URL.from_target("/", "http", "example.com")
        assert url.port is None

    def test_empty_query_string(self):
        url = URL.from_target("/?", "http", "example.com")
        assert url.query == ""

    def test_query_with_multiple_params(self):
        url = URL.from_target("/search?q=foo&page=2&sort=asc", "http", "example.com")
        assert url.query == "q=foo&page=2&sort=asc"

    def test_path_with_percent_encoding(self):
        url = URL.from_target("/path%20with%20spaces", "http", "example.com")
        assert url.path == "/path%20with%20spaces"

    def test_query_with_equals_in_value(self):
        url = URL.from_target("/go?redirect=http%3A%2F%2Fother.com", "http", "example.com")
        assert url.query == "redirect=http%3A%2F%2Fother.com"


# ---------------------------------------------------------------------------
# URL.from_target — absolute-form (RFC 9110 §7.1)
# ---------------------------------------------------------------------------

class TestURLAbsoluteForm:
    """RFC 9110 §7.1: absolute-form carries the full URI in the request line."""

    def test_http_url(self):
        url = URL.from_target("http://example.com/path", "http", "")
        assert url.scheme == "http"
        assert url.host == "example.com"
        assert url.port is None
        assert url.path == "/path"

    def test_https_url(self):
        url = URL.from_target("https://secure.example.com/api", "http", "")
        assert url.scheme == "https"
        assert url.host == "secure.example.com"

    def test_explicit_port_in_absolute_url(self):
        url = URL.from_target("http://example.com:8080/path", "http", "")
        assert url.port == 8080
        assert url.host == "example.com"

    def test_query_string_preserved(self):
        url = URL.from_target("http://example.com/search?q=test&lang=en", "http", "")
        assert url.query == "q=test&lang=en"

    def test_fragment_in_absolute_form_rejected(self):
        """RFC 9112 §3.2: request targets MUST NOT contain fragment identifiers."""
        with pytest.raises(ValueError):
            URL.from_target("http://example.com/page?x=1#anchor", "http", "")

    def test_root_path_implicit(self):
        url = URL.from_target("http://example.com/", "http", "")
        assert url.path == "/"

    def test_scheme_lowercased(self):
        """RFC 3986 §3.1: scheme is case-insensitive and normalized to lowercase."""
        url = URL.from_target("HTTP://example.com/", "http", "")
        assert url.scheme == "http"

    def test_host_lowercased(self):
        """RFC 3986 §3.2.2: host is case-insensitive and normalized to lowercase."""
        url = URL.from_target("http://Example.COM/path", "http", "")
        assert url.host == "example.com"

    def test_absolute_form_overrides_scheme_argument(self):
        """The scheme in the absolute-form URI must take precedence."""
        url = URL.from_target("https://example.com/secure", "http", "other.com")
        assert url.scheme == "https"
        assert url.host == "example.com"


# ---------------------------------------------------------------------------
# URL.from_target — authority-form (RFC 9110 §9.3.6 CONNECT)
# ---------------------------------------------------------------------------

class TestURLAuthorityForm:
    """RFC 9110 §7.1: authority-form is used exclusively with CONNECT."""

    def test_host_and_port(self):
        url = URL.from_target("example.com:443", "https", "")
        assert url.host == "example.com"
        assert url.port == 443
        assert url.path == ""

    def test_ipv4_and_port(self):
        url = URL.from_target("192.0.2.1:8080", "http", "")
        assert url.host == "192.0.2.1"
        assert url.port == 8080

    def test_no_query_or_fragment(self):
        url = URL.from_target("example.com:80", "http", "")
        assert url.query == ""
        assert url.fragment == ""


# ---------------------------------------------------------------------------
# URL.from_target — asterisk-form (RFC 9110 §7.1, OPTIONS)
# ---------------------------------------------------------------------------

class TestURLAsteriskForm:
    """RFC 9110 §7.1: asterisk-form '*' applies to the server as a whole."""

    def test_path_is_asterisk(self):
        url = URL.from_target("*", "http", "example.com")
        assert url.path == "*"

    def test_scheme_and_host_from_context(self):
        url = URL.from_target("*", "https", "example.com:8443")
        assert url.scheme == "https"
        assert url.host == "example.com"
        assert url.port == 8443

    def test_no_query_or_fragment(self):
        url = URL.from_target("*", "http", "example.com")
        assert url.query == ""
        assert url.fragment == ""


# ---------------------------------------------------------------------------
# URL properties
# ---------------------------------------------------------------------------

class TestURLProperties:

    def test_netloc_without_port(self):
        url = URL.from_target("/", "http", "example.com")
        assert url.netloc == "example.com"

    def test_netloc_with_port(self):
        url = URL.from_target("/", "http", "example.com:8080")
        assert url.netloc == "example.com:8080"

    def test_effective_port_http_default(self):
        url = URL.from_target("/", "http", "example.com")
        assert url.effective_port == 80

    def test_effective_port_https_default(self):
        url = URL.from_target("/", "https", "example.com")
        assert url.effective_port == 443

    def test_effective_port_explicit_overrides_default(self):
        url = URL.from_target("/", "https", "example.com:8443")
        assert url.effective_port == 8443

    def test_params_empty_query(self):
        url = URL.from_target("/", "http", "example.com")
        assert url.params == {}

    def test_params_single(self):
        url = URL.from_target("/?key=value", "http", "example.com")
        assert url.params == {"key": ["value"]}

    def test_params_multiple_values_same_key(self):
        """RFC 3986 allows repeated keys; parse_qs collects them into a list."""
        url = URL.from_target("/?a=1&a=2&a=3", "http", "example.com")
        assert url.params == {"a": ["1", "2", "3"]}

    def test_params_multiple_keys(self):
        url = URL.from_target("/search?q=test&page=2&sort=asc", "http", "example.com")
        assert url.params["q"] == ["test"]
        assert url.params["page"] == ["2"]
        assert url.params["sort"] == ["asc"]

    def test_params_blank_value(self):
        url = URL.from_target("/?empty=", "http", "example.com")
        assert url.params == {"empty": [""]}

    def test_str_origin_form(self):
        url = URL.from_target("/path?q=1", "http", "example.com")
        assert str(url) == "http://example.com/path?q=1"

    def test_str_with_fragment_rejected(self):
        """RFC 9112 §3.2: request targets MUST NOT contain fragment identifiers."""
        with pytest.raises(ValueError):
            URL.from_target("/path?q=1#sec", "http", "example.com")

    def test_str_asterisk_form(self):
        url = URL.from_target("*", "http", "example.com")
        assert str(url) == "*"

    def test_str_with_port(self):
        url = URL.from_target("/api", "https", "example.com:8443")
        assert str(url) == "https://example.com:8443/api"

    def test_str_no_query(self):
        url = URL.from_target("/page", "https", "example.com")
        assert str(url) == "https://example.com/page"


# ---------------------------------------------------------------------------
# IPv6 host in URL
# ---------------------------------------------------------------------------

class TestURLIPv6:
    def test_ipv6_in_host_header(self):
        url = URL.from_target("/", "http", "[::1]:8080")
        assert url.host == "[::1]"
        assert url.port == 8080

    def test_ipv6_no_port(self):
        url = URL.from_target("/", "http", "[::1]")
        assert url.host == "[::1]"
        assert url.port is None

    def test_ipv6_in_absolute_form(self):
        url = URL.from_target("http://[::1]:9000/path", "http", "")
        assert url.host == "[::1]"
        assert url.port == 9000
        assert url.path == "/path"


# ---------------------------------------------------------------------------
# Request.url integration
# ---------------------------------------------------------------------------

class TestRequestURL:
    """Verify that Request.url is built correctly from target + scheme + Host header."""

    def _make(self, target: str, scheme: str = "http", host: str = "example.com", **kwargs) -> Request:
        headers = Headers({"Host": host})
        return Request(method="GET", target=target, scheme=scheme, headers=headers, **kwargs)

    def test_url_path_matches_target(self):
        req = self._make("/api/v1?key=val")
        assert req.url.path == "/api/v1"
        assert req.url.query == "key=val"

    def test_url_scheme_from_request(self):
        req = self._make("/", scheme="https")
        assert req.url.scheme == "https"

    def test_url_host_from_host_header(self):
        req = self._make("/", host="myhost.example.com")
        assert req.url.host == "myhost.example.com"

    def test_url_port_from_host_header(self):
        req = self._make("/", host="example.com:9090")
        assert req.url.port == 9090

    def test_url_params_accessible(self):
        req = self._make("/search?q=hello&lang=en")
        assert req.url.params["q"] == ["hello"]
        assert req.url.params["lang"] == ["en"]

    def test_url_str_full(self):
        req = self._make("/path?x=1", scheme="https", host="secure.example.com")
        assert str(req.url) == "https://secure.example.com/path?x=1"

    def test_url_not_in_init_signature(self):
        """url must be computed automatically; callers must not provide it."""
        import inspect
        sig = inspect.signature(Request.__init__)
        assert "url" not in sig.parameters

    def test_url_recomputed_per_instance(self):
        req1 = self._make("/a", host="host1.com")
        req2 = self._make("/b", host="host2.com")
        assert req1.url.host == "host1.com"
        assert req2.url.host == "host2.com"

    def test_absolute_form_target(self):
        """When the target is an absolute URI, URL fields come from the URI itself."""
        headers = Headers({"Host": "proxy.example.com"})
        req = Request(method="GET", target="http://origin.example.com/resource",
                      scheme="http", headers=headers)
        assert req.url.host == "origin.example.com"
        assert req.url.path == "/resource"

    def test_connect_method_authority_form(self):
        headers = Headers({"Host": "example.com"})
        req = Request(method="CONNECT", target="tunnel.example.com:443",
                      scheme="https", headers=headers)
        assert req.url.host == "tunnel.example.com"
        assert req.url.port == 443

    def test_options_asterisk_form(self):
        headers = Headers({"Host": "example.com"})
        req = Request(method="OPTIONS", target="*",
                      scheme="http", headers=headers)
        assert req.url.path == "*"
        assert str(req.url) == "*"

    def test_url_without_host_header(self):
        """If the Host header is absent, host and port are empty/None."""
        req = Request(method="GET", target="/path", scheme="http")
        assert req.url.path == "/path"
        assert req.url.host == ""
        assert req.url.port is None
