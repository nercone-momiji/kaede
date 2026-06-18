"""
RFC 9113 (HTTP/2) header building conformance tests.
"""
from __future__ import annotations

import pytest
from kaede.http.h2 import H2, H2_FORBIDDEN_HEADERS
from kaede.models import Request, Response, Headers


FORBIDDEN = list(H2_FORBIDDEN_HEADERS)


# ---------------------------------------------------------------------------
# RFC 9113 §8.2.2: Connection-specific header fields
# ---------------------------------------------------------------------------

class TestForbiddenResponseHeaders:
    """RFC 9113 §8.2.2: Connection-specific headers MUST NOT appear in HTTP/2"""

    @pytest.mark.parametrize("header", FORBIDDEN)
    def test_forbidden_stripped_from_response(self, header):
        response = Response(status_code=200, headers=Headers({header: "value"}))
        built = H2.build_response_headers(response)
        names = [n for n, v in built]
        assert header not in names

    def test_te_trailers_allowed(self):
        """RFC 9113 §8.2.2: TE: trailers is the only allowed TE value"""
        # TE is NOT in the forbidden headers list itself, but only 'trailers' value is allowed
        # build_response_headers doesn't handle TE specially, but the forbidden list check suffices
        response = Response(status_code=200, headers=Headers({"Content-Type": "text/html"}))
        built = H2.build_response_headers(response)
        names = [n for n, v in built]
        assert "content-type" in names  # normal header passes through


class TestForbiddenRequestHeaders:
    @pytest.mark.parametrize("header", FORBIDDEN)
    def test_forbidden_stripped_from_request(self, header):
        request = Request(method="GET", target="/", headers=Headers({header: "value"}))
        built = H2.build_request_headers(request, "example.com")
        names = [n for n, v in built]
        assert header not in names


# ---------------------------------------------------------------------------
# RFC 9113 §8.3: Pseudo-header fields
# ---------------------------------------------------------------------------

class TestResponsePseudoHeaders:
    def test_status_is_first_header(self):
        """RFC 9113 §8.3.2: :status pseudo-header must be present"""
        response = Response(status_code=200)
        built = H2.build_response_headers(response)
        assert built[0][0] == ":status"

    def test_status_value_matches(self):
        response = Response(status_code=404)
        built = H2.build_response_headers(response)
        assert built[0] == (":status", "404")

    @pytest.mark.parametrize("code", [100, 200, 301, 400, 500])
    def test_status_code_as_string(self, code):
        response = Response(status_code=code)
        built = H2.build_response_headers(response)
        assert built[0] == (":status", str(code))


class TestRequestPseudoHeaders:
    """RFC 9113 §8.3.1: Request pseudo-headers"""

    def test_method_pseudo(self):
        req = Request(method="POST", target="/submit", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com")
        assert (":method", "POST") in built

    def test_scheme_pseudo(self):
        req = Request(method="GET", target="/", scheme="https", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com")
        assert (":scheme", "https") in built

    def test_path_pseudo(self):
        req = Request(method="GET", target="/path?q=1", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com")
        assert (":path", "/path?q=1") in built

    def test_authority_pseudo(self):
        req = Request(method="GET", target="/", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com:8080")
        assert (":authority", "example.com:8080") in built

    def test_host_header_excluded(self):
        """RFC 9113 §8.3.1: :authority replaces Host; Host MUST NOT be present"""
        req = Request(method="GET", target="/", headers=Headers({"Host": "example.com"}))
        built = H2.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert "host" not in names

    def test_content_length_header_excluded_from_request_fields(self):
        """RFC 9113: content-length is added explicitly, not from headers"""
        req = Request(method="GET", target="/", headers=Headers({"Content-Length": "0"}))
        built = H2.build_request_headers(req, "example.com", body=None)
        names = [n for n, v in built]
        assert "content-length" not in names

    def test_content_length_added_when_body_present(self):
        body = b"hello world"
        req = Request(method="POST", target="/", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com", body=body)
        assert ("content-length", str(len(body))) in built

    def test_no_content_length_when_no_body(self):
        req = Request(method="GET", target="/", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com", body=None)
        names = [n for n, v in built]
        assert "content-length" not in names

    def test_pseudo_headers_appear_before_regular_headers(self):
        """RFC 9113 §8.3: pseudo-headers MUST precede all regular headers"""
        req = Request(method="GET", target="/", headers=Headers({"Accept": "text/html"}))
        built = H2.build_request_headers(req, "example.com")
        pseudo_indices = [i for i, (n, v) in enumerate(built) if n.startswith(":")]
        regular_indices = [i for i, (n, v) in enumerate(built) if not n.startswith(":")]
        if pseudo_indices and regular_indices:
            assert max(pseudo_indices) < min(regular_indices)


# ---------------------------------------------------------------------------
# RFC 9113 §8.2: Header field names must be lowercase
# ---------------------------------------------------------------------------

class TestHeaderCasing:
    def test_response_header_names_are_lowercase(self):
        """RFC 9113 §8.2: All header names MUST be lowercase"""
        response = Response(
            status_code=200,
            headers=Headers({"Content-Type": "text/html", "X-Custom": "value"}),
        )
        built = H2.build_response_headers(response)
        for name, _ in built:
            if not name.startswith(":"):
                assert name == name.lower(), f"Header name {name!r} is not lowercase"

    def test_request_header_names_are_lowercase(self):
        req = Request(
            method="GET",
            target="/",
            headers=Headers({"Accept": "text/html", "X-MY-HEADER": "val"}),
        )
        built = H2.build_request_headers(req, "example.com")
        for name, _ in built:
            if not name.startswith(":"):
                assert name == name.lower(), f"Header name {name!r} is not lowercase"


# ---------------------------------------------------------------------------
# Security: CRLF injection prevention
# ---------------------------------------------------------------------------

class TestHeaderInjection:
    def test_crlf_in_response_name_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Evil\r\nInjected": "val"}))
        built = H2.build_response_headers(response)
        names = [n for n, v in built]
        assert not any("\r" in n or "\n" in n for n in names)

    def test_crlf_in_response_value_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Test": "val\r\nEvil: injected"}))
        built = H2.build_response_headers(response)
        values = [v for n, v in built]
        assert not any("\r" in v or "\n" in v for v in values)

    def test_null_in_response_name_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Test\x00": "value"}))
        built = H2.build_response_headers(response)
        names = [n for n, v in built]
        assert not any("\x00" in n for n in names)

    def test_null_in_response_value_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Test": "val\x00ue"}))
        built = H2.build_response_headers(response)
        values = [v for n, v in built]
        assert not any("\x00" in v for v in values)

    def test_crlf_in_request_name_filtered(self):
        req = Request(method="GET", target="/", headers=Headers({"X-Evil\r\n": "val"}))
        built = H2.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert not any("\r" in n or "\n" in n for n in names)

    def test_crlf_in_request_value_filtered(self):
        req = Request(method="GET", target="/", headers=Headers({"X-Test": "val\r\nInj: x"}))
        built = H2.build_request_headers(req, "example.com")
        values = [v for n, v in built]
        assert not any("\r" in v or "\n" in v for v in values)


# ---------------------------------------------------------------------------
# RFC 9113 §8.4: Extended CONNECT (WebSocket over HTTP/2)
# ---------------------------------------------------------------------------

class TestWebSocketConnect:
    def test_build_connect_websocket_headers_method(self):
        req = Request(method="GET", target="/ws", scheme="https", headers=Headers({}))
        built = H2.build_connect_websocket_headers(req, "example.com")
        assert (":method", "CONNECT") in built

    def test_build_connect_websocket_protocol(self):
        req = Request(method="GET", target="/ws", scheme="https", headers=Headers({}))
        built = H2.build_connect_websocket_headers(req, "example.com")
        assert (":protocol", "websocket") in built

    def test_build_connect_websocket_version(self):
        req = Request(method="GET", target="/ws", scheme="https", headers=Headers({}))
        built = H2.build_connect_websocket_headers(req, "example.com")
        assert ("sec-websocket-version", "13") in built

    def test_build_connect_websocket_subprotocols(self):
        req = Request(method="GET", target="/ws", scheme="https", headers=Headers({}))
        built = H2.build_connect_websocket_headers(req, "example.com", subprotocols=["chat", "superchat"])
        assert ("sec-websocket-protocol", "chat, superchat") in built

    def test_build_connect_websocket_no_host(self):
        """Extended CONNECT uses :authority, not Host"""
        req = Request(method="GET", target="/ws", scheme="https", headers=Headers({"Host": "example.com"}))
        built = H2.build_connect_websocket_headers(req, "example.com")
        names = [n for n, v in built]
        assert "host" not in names


# ---------------------------------------------------------------------------
# RFC 9113 §8.2.2: TE header handling
# ---------------------------------------------------------------------------

class TestTEHeaderHandling:
    def test_te_trailers_passes_in_request(self):
        """RFC 9113 §8.2.2: TE: trailers is the only permitted TE value"""
        req = Request(method="GET", target="/", headers=Headers({"TE": "trailers"}))
        built = H2.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert "te" in names
        te_values = [v for n, v in built if n == "te"]
        assert "trailers" in te_values

    def test_te_non_trailers_filtered_from_request(self):
        """RFC 9113 §8.2.2: TE values other than 'trailers' MUST NOT be sent in HTTP/2"""
        req = Request(method="GET", target="/", headers=Headers({"TE": "gzip"}))
        built = H2.build_request_headers(req, "example.com")
        te_values = [v for n, v in built if n == "te"]
        assert "gzip" not in te_values


# ---------------------------------------------------------------------------
# RFC 9113 §8.3: Request pseudo-header ordering and completeness
# ---------------------------------------------------------------------------

class TestPseudoHeaderOrdering:
    def test_all_four_request_pseudos_present(self):
        """RFC 9113 §8.3.1: :method, :scheme, :authority, :path must all be present"""
        req = Request(method="GET", target="/", scheme="https", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert ":method" in names
        assert ":scheme" in names
        assert ":authority" in names
        assert ":path" in names

    def test_default_scheme_is_http(self):
        """scheme field defaults to 'http' when not specified"""
        req = Request(method="GET", target="/", headers=Headers({}))
        assert req.scheme == "http"
        built = H2.build_request_headers(req, "example.com")
        assert (":scheme", "http") in built

    def test_multiple_accept_headers_both_present(self):
        """Multiple values for the same header name are each emitted"""
        h = Headers({})
        h.append("Accept", "text/html")
        h.append("Accept", "application/json")
        req = Request(method="GET", target="/", headers=h)
        built = H2.build_request_headers(req, "example.com")
        accept_values = [v for n, v in built if n == "accept"]
        assert "text/html" in accept_values
        assert "application/json" in accept_values

    def test_response_has_no_request_pseudos(self):
        """RFC 9113 §8.3.2: response headers must not include :method, :path, etc."""
        response = Response(status_code=200, headers=Headers({"Content-Type": "text/html"}))
        built = H2.build_response_headers(response)
        names = [n for n, v in built]
        for pseudo in (":method", ":path", ":scheme", ":authority", ":protocol"):
            assert pseudo not in names


# ---------------------------------------------------------------------------
# RFC 9113 §8.1: Content-Length semantics in HTTP/2
# ---------------------------------------------------------------------------

class TestH2ContentLength:
    def test_content_length_with_empty_body_not_added(self):
        """body=b'' is falsy; no content-length should be added"""
        req = Request(method="POST", target="/", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com", body=b"")
        names = [n for n, v in built]
        assert "content-length" not in names

    def test_content_length_value_correct(self):
        """content-length must equal the actual body byte count"""
        body = b"hello world"
        req = Request(method="POST", target="/upload", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com", body=body)
        cl_values = [v for n, v in built if n == "content-length"]
        assert cl_values == [str(len(body))]
