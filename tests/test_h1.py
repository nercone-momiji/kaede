"""
RFC 9112 (HTTP/1.1 Message Syntax) conformance tests.
Validates against the RFC specification, not current Kaede behavior.
"""
from __future__ import annotations

import pytest
import ipaddress

from kaede.http.models import Request, Response, Headers
from kaede.http.h1 import H1, HTTPVersionNotSupportedError, HTTPMethodNotImplementedError

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)

# RFC 9112 §3: Request line

class TestRequestLine:
    def test_valid_get(self):
        req = H1.parse_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)
        assert req.method == "GET"
        assert req.target == "/"
        assert req.protocol == "HTTP/1.1"

    def test_fragment_in_target_rejected(self):
        """RFC 9112 §3.2: Request targets MUST NOT contain fragment identifiers."""
        with pytest.raises(ValueError):
            H1.parse_request(b"GET /path?q=1#frag HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)

    @pytest.mark.parametrize("method", [
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
    ])
    def test_all_valid_methods(self, method):
        data = f"{method} / HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        req = H1.parse_request(data, client=CLIENT)
        assert req.method == method

    def test_unknown_method_raises_501(self):
        """RFC 9110 §9: Unknown methods should result in 501"""
        with pytest.raises(HTTPMethodNotImplementedError):
            H1.parse_request(b"BREW / HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)

    def test_http20_raises_505(self):
        with pytest.raises(HTTPVersionNotSupportedError):
            H1.parse_request(b"GET / HTTP/2.0\r\nHost: example.com\r\n\r\n", client=CLIENT)

    def test_missing_header_terminator_raises(self):
        """RFC 9112 §2.1: Incomplete requests must be rejected"""
        with pytest.raises(ValueError):
            H1.parse_request(b"GET / HTTP/1.1\r\nHost: example.com", client=CLIENT)

    def test_malformed_request_line_raises(self):
        with pytest.raises(ValueError):
            H1.parse_request(b"GET /\r\nHost: example.com\r\n\r\n", client=CLIENT)

    def test_null_in_target_raises(self):
        """RFC 9112 §3.2: NUL in request target is invalid"""
        with pytest.raises(ValueError):
            H1.parse_request(b"GET /foo\x00bar HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)

    def test_cr_in_target_raises(self):
        with pytest.raises(ValueError):
            H1.parse_request(b"GET /foo\rbar HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)

    def test_lf_in_target_raises(self):
        with pytest.raises(ValueError):
            H1.parse_request(b"GET /foo\nbar HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)

# RFC 9110 §7.2: Host header

class TestHostHeader:
    def test_missing_host_raises(self):
        """RFC 9112 §3.2 / RFC 9110 §7.2: Host MUST be present in HTTP/1.1"""
        with pytest.raises(ValueError, match="(?i)missing|host"):
            H1.parse_request(b"GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n", client=CLIENT)

    def test_host_present_succeeds(self):
        req = H1.parse_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", client=CLIENT)
        assert req.headers.get("Host") == "example.com"

# RFC 9110 §5.1 / RFC 9112 §5: Header fields

class TestHeaderFields:
    def test_obs_fold_rejected(self):
        """RFC 9112 §5.1: obs-fold (line folding) MUST be rejected"""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Hdr: val\r\n  cont\r\n\r\n"
        with pytest.raises(ValueError):
            H1.parse_request(data, client=CLIENT)

    def test_whitespace_before_colon_rejected(self):
        """RFC 9112 §5.1: no whitespace between field name and colon"""
        data = b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n"
        with pytest.raises(ValueError):
            H1.parse_request(data, client=CLIENT)

    def test_tab_before_colon_rejected(self):
        data = b"GET / HTTP/1.1\r\nHost\t: example.com\r\n\r\n"
        with pytest.raises(ValueError):
            H1.parse_request(data, client=CLIENT)

    def test_invalid_tchar_in_name_rejected(self):
        """RFC 9110 §5.1: field name must be a token (valid TCHAR characters)"""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nX Bad: value\r\n\r\n"
        with pytest.raises(ValueError):
            H1.parse_request(data, client=CLIENT)

    def test_header_without_colon_rejected(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nBadHeader\r\n\r\n"
        with pytest.raises(ValueError):
            H1.parse_request(data, client=CLIENT)

    def test_header_value_ows_stripped(self):
        """RFC 9110 §5.5: Optional whitespace around field value must be stripped"""
        req = H1.parse_request(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom:   hello   \r\n\r\n",
            client=CLIENT,
        )
        assert req.headers.get("X-Custom") == "hello"

    def test_multiple_values_same_field(self):
        """RFC 9110 §5.2: Multiple occurrences of same field are allowed"""
        req = H1.parse_request(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n",
            client=CLIENT,
        )
        accept = req.headers.get("Accept")
        assert "text/html" in accept
        assert "application/json" in accept

# RFC 9110 §8.6 / RFC 9112 §6.3: Content-Length

class TestContentLength:
    def test_content_length_zero_body_empty(self):
        # RFC 9110 §8.6: Content-Length: 0 means an explicit empty body, not absent body
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b""

    def test_content_length_exact(self):
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            client=CLIENT,
        )
        assert req.body == b"hello"

    def test_content_length_leading_zero_rejected(self):
        """RFC 9110 §8.6: leading zeros are invalid"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 05\r\n\r\nhello",
                client=CLIENT,
            )

    def test_negative_content_length_rejected(self):
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: -1\r\n\r\n",
                client=CLIENT,
            )

    def test_non_numeric_content_length_rejected(self):
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: abc\r\n\r\n",
                client=CLIENT,
            )

    def test_both_te_and_cl_rejected(self):
        """RFC 9112 §6.3: TE + CL together MUST be rejected"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\n"
                b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n",
                client=CLIENT,
            )

    def test_max_body_size_enforced(self):
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
                client=CLIENT,
                max_body_size=4,
            )

# RFC 9112 §7.1: Chunked transfer encoding

class TestChunkedEncoding:
    def test_single_chunk(self):
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"hello"

    def test_multiple_chunks(self):
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"hello world"

    def test_empty_chunked_body(self):
        # RFC 9112 §7.1: Transfer-Encoding: chunked with only terminal chunk = explicit empty body
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b""

    def test_chunk_extension_ignored(self):
        """RFC 9112 §7.1.1: chunk-ext values are ignored"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5;ext=val\r\nhello\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"hello"

    def test_chunk_size_hex(self):
        """RFC 9112 §7.1: chunk size is hexadecimal"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"a\r\n0123456789\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"0123456789"

    def test_chunk_missing_crlf_terminator_raises(self):
        """RFC 9112 §7.1: each chunk must end with CRLF"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhelloXXXXX\r\n0\r\n\r\n",  # wrong CRLF position
                client=CLIENT,
            )

    def test_invalid_chunk_size_raises(self):
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"ZZZ\r\nhello\r\n0\r\n\r\n",
                client=CLIENT,
            )

    def test_chunked_must_be_last_encoding(self):
        """RFC 9110 §8.7: 'chunked' must be the final Transfer-Encoding"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked,gzip\r\n\r\n"
                b"0\r\n\r\n",
                client=CLIENT,
            )

    def test_chunked_duplicate_rejected(self):
        """RFC 9112 §6.1: 'chunked' must appear exactly once"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked,chunked\r\n\r\n"
                b"0\r\n\r\n",
                client=CLIENT,
            )

    def test_chunked_trailer_fields_skipped(self):
        """RFC 9112 §7.1.2: trailer fields after last chunk are allowed"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"hello"

    def test_chunked_max_body_size(self):
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n",
                client=CLIENT,
                max_body_size=4,
            )

# RFC 9110 §6.4: Responses without a body

class TestResponseHasNoBody:
    @pytest.mark.parametrize("status", [100, 101, 102, 103, 199])
    def test_1xx_no_body(self, status):
        assert H1.response_has_no_body(status, "GET") is True

    def test_204_no_body(self):
        assert H1.response_has_no_body(204, "GET") is True

    def test_205_no_body(self):
        assert H1.response_has_no_body(205, "GET") is True

    def test_304_no_body(self):
        assert H1.response_has_no_body(304, "GET") is True

    def test_head_always_no_body(self):
        """RFC 9110 §9.3.2: HEAD response never has a body"""
        assert H1.response_has_no_body(200, "HEAD") is True
        assert H1.response_has_no_body(404, "HEAD") is True

    def test_200_get_has_body(self):
        assert H1.response_has_no_body(200, "GET") is False

    def test_200_post_has_body(self):
        assert H1.response_has_no_body(200, "POST") is False

    def test_404_has_body(self):
        assert H1.response_has_no_body(404, "GET") is False

# RFC 9112 §4: Response format building

class TestBuildResponseHead:
    def test_status_line_format(self):
        """RFC 9112 §4: HTTP-version SP status-code SP reason-phrase CRLF"""
        result = H1.build_response_head(Response(status_code=200))
        assert result.startswith(b"HTTP/1.1 200 ")

    def test_ends_with_double_crlf(self):
        result = H1.build_response_head(Response(status_code=404))
        assert result.endswith(b"\r\n\r\n")

    def test_known_status_phrase(self):
        result = H1.build_response_head(Response(status_code=404))
        assert b"Not Found" in result

    def test_crlf_injection_in_header_name_prevented(self):
        """RFC 9112 §5: CRLF injection must not be possible"""
        response = Response(status_code=200, headers=Headers({"X-Evil\r\nInjected": "val"}))
        result = H1.build_response_head(response)
        assert b"Injected" not in result

    def test_crlf_injection_in_header_value_prevented(self):
        response = Response(status_code=200, headers=Headers({"X-Test": "val\r\nEvil: hdr"}))
        result = H1.build_response_head(response)
        assert b"Evil: hdr" not in result

    def test_null_byte_in_header_prevented(self):
        response = Response(status_code=200, headers=Headers({"X-Test": "val\x00ue"}))
        result = H1.build_response_head(response)
        assert b"\x00" not in result

    def test_normal_headers_included(self):
        response = Response(status_code=200, headers=Headers({"Content-Type": "text/html"}))
        result = H1.build_response_head(response)
        assert b"content-type: text/html\r\n" in result

# RFC 9112 §3: Request building

class TestBuildRequest:
    def test_request_line_format(self):
        req = Request(method="GET", target="/path", headers=Headers({"Host": "example.com"}))
        result = H1.build_request_head(req)
        assert result.startswith(b"GET /path HTTP/1.1\r\n")

    def test_ends_with_double_crlf(self):
        req = Request(method="GET", target="/", headers=Headers({"Host": "example.com"}))
        result = H1.build_request_head(req)
        assert result.endswith(b"\r\n\r\n")

    def test_with_body(self):
        req = Request(method="POST", target="/", headers=Headers({"Host": "example.com"}), body=b"data")
        result = H1.build_request(req)
        assert result.endswith(b"data")

    def test_without_body(self):
        req = Request(method="GET", target="/", headers=Headers({"Host": "example.com"}))
        result = H1.build_request(req)
        assert isinstance(result, bytes)
        assert result.endswith(b"\r\n\r\n")

    def test_crlf_injection_in_header_prevented(self):
        req = Request(method="GET", target="/", headers=Headers({"X-H\r\nInj": "v"}))
        result = H1.build_request_head(req)
        assert b"Inj" not in result

# RFC 9112 §4: Response parsing

class TestParseResponse:
    def test_200_with_content_length(self):
        resp = H1.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        assert resp.status_code == 200
        assert resp.body == b"hello"

    def test_204_no_body(self):
        resp = H1.parse_response(b"HTTP/1.1 204 No Content\r\n\r\n")
        assert resp.status_code == 204
        assert resp.body is None

    def test_head_no_body(self):
        """RFC 9110 §9.3.2: HEAD response MUST NOT have a body"""
        resp = H1.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", method="HEAD")
        assert resp.body is None

    def test_chunked_response(self):
        resp = H1.parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        assert resp.body == b"hello"

    def test_response_without_body_length_reads_to_eof(self):
        """RFC 9112 §6.3: response with no length framing reads until close"""
        resp = H1.parse_response(b"HTTP/1.1 200 OK\r\n\r\nbody data")
        assert resp.body == b"body data"

    def test_invalid_status_code_raises(self):
        with pytest.raises(ValueError):
            H1.parse_response(b"HTTP/1.1 99 Too Short\r\n\r\n")

    def test_status_code_must_be_3_digits(self):
        with pytest.raises(ValueError):
            H1.parse_response(b"HTTP/1.1 1000 Too Long\r\n\r\n")

    def test_1xx_informational_status_parsed(self):
        status, _, _, _ = H1.parse_response_head(b"HTTP/1.1 100 Continue")
        assert status == 100

    def test_obs_fold_in_response_rejected(self):
        with pytest.raises(ValueError):
            H1.parse_response(
                b"HTTP/1.1 200 OK\r\nX-Hdr: val\r\n  cont\r\n\r\n"
            )

    def test_whitespace_before_colon_in_response_rejected(self):
        with pytest.raises(ValueError):
            H1.parse_response(b"HTTP/1.1 200 OK\r\nX-Test : value\r\n\r\n")

# RFC 9112 §7.1.2: scan_chunked

class TestScanChunked:
    def test_incomplete_returns_none(self):
        result = H1.scan_chunked(b"5\r\nhel")
        assert result is None

    def test_complete_returns_body_and_offset(self):
        data = b"5\r\nhello\r\n0\r\n\r\n"
        result = H1.scan_chunked(data)
        assert result is not None
        body, offset = result
        assert body == b"hello"
        assert offset == len(data)

    def test_empty_returns_empty_body(self):
        # RFC 9112 §7.1: terminal-only chunked body is an explicit empty body (b""), not absent (None)
        data = b"0\r\n\r\n"
        result = H1.scan_chunked(data)
        assert result is not None
        body, _ = result
        assert body == b""

    def test_negative_chunk_size_raises(self):
        with pytest.raises(ValueError):
            H1.scan_chunked(b"-1\r\nhello\r\n0\r\n\r\n")

# RFC 9110 §7.2: Multiple Host headers

class TestMultipleHostHeader:
    def test_multiple_host_headers_rejected(self):
        """RFC 9110 §7.2: More than one Host field MUST cause 400 rejection"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n",
                client=CLIENT,
            )

    def test_single_host_header_accepted(self):
        req = H1.parse_request(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            client=CLIENT,
        )
        assert req.headers.get("Host") == "example.com"

# RFC 9112 §6.3: Multiple Content-Length fields

class TestMultipleContentLength:
    def test_multiple_content_length_same_value_accepted(self):
        """RFC 9112 §6.3: Multiple CL with identical value MUST be treated as one"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\n"
            b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            client=CLIENT,
        )
        assert req.body == b"hello"

    def test_multiple_content_length_different_values_rejected(self):
        """RFC 9112 §6.3: Multiple CL with differing values MUST be rejected"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\n"
                b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
                client=CLIENT,
            )

# RFC 9112 §3.2 / §3.3: Request-target validation

class TestRequestTargetValidation:
    def test_empty_target_rejected(self):
        """RFC 9112 §3.2: An empty request-target is invalid"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"GET  HTTP/1.1\r\nHost: example.com\r\n\r\n",
                client=CLIENT,
            )

    def test_options_asterisk_target_valid(self):
        """RFC 9112 §3.4: OPTIONS may use asterisk-form '*'"""
        req = H1.parse_request(
            b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
            client=CLIENT,
        )
        assert req.target == "*"

    def test_absolute_form_target_valid(self):
        """RFC 9112 §3.2.2: absolute-form request-target is valid"""
        req = H1.parse_request(
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            client=CLIENT,
        )
        assert req.target == "http://example.com/path"

    def test_connect_with_authority_target(self):
        """RFC 9112 §3.3: CONNECT uses authority-form (host:port)"""
        req = H1.parse_request(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            client=CLIENT,
        )
        assert req.target == "example.com:443"
        assert req.method == "CONNECT"

# RFC 9112 §6.2: Body framing edge cases

class TestBodyParsing:
    def test_content_length_body_truncated_at_cl(self):
        """RFC 9112 §6.2: only Content-Length bytes are read as body"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nhello",
            client=CLIENT,
        )
        assert req.body == b"hel"

    def test_body_size_exactly_at_max_succeeds(self):
        """Body equal to max_body_size must succeed"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            client=CLIENT,
            max_body_size=5,
        )
        assert req.body == b"hello"

    def test_post_no_content_framing_no_body(self):
        """POST with no Content-Length and no Transfer-Encoding has body=None"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            client=CLIENT,
        )
        assert req.body is None

    def test_get_with_body_content_length(self):
        """GET can carry a body when Content-Length is present"""
        req = H1.parse_request(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ndata",
            client=CLIENT,
        )
        assert req.body == b"data"

# RFC 9112 §7.1: Chunked encoding hex-digit edge cases

class TestChunkedHexEdgeCases:
    def test_chunk_size_uppercase_hex(self):
        """RFC 9112 §7.1: HEXDIG includes A-F (uppercase)"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"A\r\n0123456789\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"0123456789"

    def test_chunk_size_mixed_case_hex(self):
        """RFC 9112 §7.1: Mixed-case HEXDIG is valid (Ff = 255 decimal)"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"Ff\r\n" + b"x" * 255 + b"\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"x" * 255

    def test_chunk_size_with_leading_zero_hex(self):
        """Leading zeros in hexadecimal chunk size are valid"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0a\r\n0123456789\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"0123456789"

    def test_multiple_chunk_extensions(self):
        """RFC 9112 §7.1.1: Multiple semicolons in chunk-ext are ignored"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5;a=1;b=2\r\nhello\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"hello"

# RFC 9112 §6.1: Transfer-Encoding validation

class TestTransferEncodingValidation:
    def test_transfer_encoding_identity_rejected(self):
        """TE: identity is not 'chunked'; any non-chunked final encoding must be rejected"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: identity\r\n\r\n",
                client=CLIENT,
            )

    def test_transfer_encoding_gzip_only_rejected(self):
        """TE: gzip alone (without chunked as final) must be rejected"""
        with pytest.raises(ValueError):
            H1.parse_request(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n",
                client=CLIENT,
            )

    def test_transfer_encoding_gzip_then_chunked_accepted(self):
        """RFC 9112 §6.1: multiple TEs are allowed if 'chunked' is last"""
        req = H1.parse_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n",
            client=CLIENT,
        )
        assert req.body == b"hello"

# RFC 9112 §4: Response parsing edge cases

class TestResponseParsingEdgeCases:
    def test_response_content_length_exceeds_max_body_size(self):
        """Content-Length exceeding max_body_size must raise ValueError"""
        with pytest.raises(ValueError):
            H1.parse_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                max_body_size=4,
            )

    def test_response_chunked_exceeds_max_body_size(self):
        """Chunked body exceeding max_body_size must raise ValueError"""
        with pytest.raises(ValueError):
            H1.parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n",
                max_body_size=4,
            )

    @pytest.mark.parametrize("code", [200, 301, 400, 500, 600, 700, 999])
    def test_three_digit_status_codes_parseable(self, code):
        """Any 3-digit status code is syntactically valid per RFC 9112"""
        status, _, _, _ = H1.parse_response_head(f"HTTP/1.1 {code} Reason".encode())
        assert status == code

    def test_response_with_both_te_and_cl_te_wins(self):
        """RFC 9112 §6.3: when both TE and CL present in response, TE governs body length"""
        resp = H1.parse_response(
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 99\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        assert resp.body == b"hello"

# RFC 9112 §4: build_response_head edge cases

class TestBuildResponseHeadEdgeCases:
    def test_non_standard_status_code_empty_phrase(self):
        """Non-standard 3-digit status codes produce an empty reason phrase"""
        result = H1.build_response_head(Response(status_code=999))
        assert b"HTTP/1.1 999 " in result
        assert result.endswith(b"\r\n\r\n")

    def test_response_with_no_headers(self):
        result = H1.build_response_head(Response(status_code=200))
        assert result == b"HTTP/1.1 200 OK\r\n\r\n"

    def test_all_headers_included_in_output(self):
        response = Response(
            status_code=200,
            headers=Headers({"Content-Type": "text/html", "X-Custom": "val"}),
        )
        result = H1.build_response_head(response)
        assert b"content-type: text/html\r\n" in result
        assert b"x-custom: val\r\n" in result

# RFC 9112 §3: build_request edge cases

class TestBuildRequestEdgeCases:
    def test_request_method_and_target_in_line(self):
        req = Request(method="DELETE", target="/resource/1", headers=Headers({"Host": "example.com"}))
        result = H1.build_request_head(req)
        assert result.startswith(b"DELETE /resource/1 HTTP/1.1\r\n")

    def test_request_with_multiple_headers(self):
        req = Request(
            method="POST",
            target="/",
            headers=Headers({"Host": "example.com", "Content-Type": "application/json"}),
        )
        result = H1.build_request_head(req)
        assert b"content-type: application/json\r\n" in result

# RFC 9112 §6: build_response return type

class TestBuildResponse:
    def test_bytes_body_returns_single_bytes(self):
        """If has_real_body is True, build_response must return a single bytes object."""
        response = Response(body=b"hello", status_code=200)
        result = H1.build_response(response)
        assert isinstance(result, bytes)
        assert result.endswith(b"hello")

    def test_bytes_body_contains_head_and_body(self):
        response = Response(body=b"world", status_code=200)
        result = H1.build_response(response)
        assert b"HTTP/1.1 200" in result
        assert b"world" in result

    def test_none_body_returns_tuple_with_none(self):
        """None body (no content): must return (head_bytes, None)."""
        response = Response(body=None, status_code=204)
        result = H1.build_response(response)
        assert isinstance(result, tuple)
        head, path = result
        assert isinstance(head, bytes)
        assert path is None

    def test_path_body_returns_tuple_with_path(self):
        """PathLike body (file send): must return (head_bytes, path)."""
        import pathlib
        p = pathlib.Path("/tmp/file.bin")
        response = Response(body=p, status_code=200)
        result = H1.build_response(response)
        assert isinstance(result, tuple)
        head, alt = result
        assert isinstance(head, bytes)
        assert alt is p

    def test_head_in_tuple_ends_with_crlf_crlf(self):
        response = Response(body=None, status_code=204)
        head, _ = H1.build_response(response)
        assert head.endswith(b"\r\n\r\n")

# RFC 9112 §7.1: decode_chunked — direct invocation

class TestDecodeChunkedDirect:
    def test_complete_single_chunk(self):
        """A single chunked body must be decoded correctly."""
        body = H1.decode_chunked(b"5\r\nhello\r\n0\r\n\r\n")
        assert body == b"hello"

    def test_multiple_chunks_concatenated(self):
        body = H1.decode_chunked(b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n")
        assert body == b"abcdefg"

    def test_empty_body_returns_empty_bytes(self):
        """RFC 9112 §7.1: zero-length chunked body is an explicit empty body (b""), not absent."""
        body = H1.decode_chunked(b"0\r\n\r\n")
        assert body == b""

    def test_incomplete_data_raises_value_error(self):
        """Incomplete chunked body must raise ValueError."""
        with pytest.raises(ValueError):
            H1.decode_chunked(b"5\r\nhell")  # truncated – no CRLF + terminal chunk

    def test_chunk_with_extension_ignored(self):
        """RFC 9112 §7.1.1: chunk extensions after ';' must be ignored."""
        body = H1.decode_chunked(b"5;ext=ignored\r\nhello\r\n0\r\n\r\n")
        assert body == b"hello"

    def test_max_body_size_enforced(self):
        with pytest.raises(ValueError):
            H1.decode_chunked(b"a\r\n" + b"x" * 10 + b"\r\n0\r\n\r\n", max_body_size=5)

    def test_missing_chunk_crlf_terminator_raises(self):
        """RFC 9112 §7.1: each chunk must end with CRLF."""
        with pytest.raises(ValueError):
            H1.decode_chunked(b"5\r\nhelloxx0\r\n\r\n")

# RFC 9112 §4: parse_response_head edge cases

class TestParseResponseHeadEdgeCases:
    def test_http10_accepted(self):
        """RFC 9112 §2.5: clients MUST accept HTTP/1.0 responses from servers."""
        status, _, _, protocol = H1.parse_response_head(b"HTTP/1.0 200 OK")
        assert status == 200
        assert protocol == "HTTP/1.0"

    def test_http11_not_flagged_as_http10(self):
        """HTTP/1.1 responses must not be flagged as HTTP/1.0."""
        _, _, _, protocol = H1.parse_response_head(b"HTTP/1.1 200 OK")
        assert protocol != "HTTP/1.0"

    def test_http20_rejected(self):
        """HTTP/2.0 version on an HTTP/1.1 parser must raise ValueError."""
        with pytest.raises(ValueError):
            H1.parse_response_head(b"HTTP/2.0 200 OK")

    def test_too_few_parts_raises(self):
        """Status line with only one token must raise ValueError."""
        with pytest.raises(ValueError):
            H1.parse_response_head(b"HTTP/1.1")

    def test_empty_reason_phrase_accepted(self):
        """RFC 9112 §4: The reason phrase MAY be empty."""
        status, phrase, _, _ = H1.parse_response_head(b"HTTP/1.1 200 ")
        assert status == 200
        assert isinstance(phrase, str)

    def test_non_numeric_status_raises(self):
        """RFC 9112 §4: status-code MUST be three decimal digits."""
        with pytest.raises(ValueError):
            H1.parse_response_head(b"HTTP/1.1 OK 200")

    def test_two_digit_status_raises(self):
        """RFC 9112 §4: status-code must be exactly three digits."""
        with pytest.raises(ValueError):
            H1.parse_response_head(b"HTTP/1.1 20 OK")

    def test_valid_response_parses_headers(self):
        status, _, headers, _ = H1.parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: val"
        )
        assert status == 200
        assert headers.get("Content-Type") == "text/html"
