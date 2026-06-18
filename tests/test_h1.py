import ipaddress
import pytest
from kaede.http.h1 import H1
from kaede.models import Request, Response

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)

class TestH1ParseRequest:
    def _parse(self, raw: bytes, **kwargs):
        return H1.parse_request(raw, client=CLIENT, **kwargs)

    def test_simple_get(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = self._parse(raw)
        assert req.method == "GET"
        assert req.target == "/"
        assert req.headers.get("Host") == "example.com"
        assert req.body is None

    def test_post_with_body(self):
        body = b'{"key": "value"}'
        raw = (
            b"POST /api HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 16\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n" + body
        )
        req = self._parse(raw)
        assert req.method == "POST"
        assert req.body == body

    def test_chunked_body(self):
        raw = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"6\r\n world\r\n"
            b"0\r\n\r\n"
        )
        req = self._parse(raw)
        assert req.body == b"hello world"

    def test_chunked_with_extension(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5;ext=ignored\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        req = self._parse(raw)
        assert req.body == b"hello"

    def test_empty_chunked_body(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        req = self._parse(raw)
        assert req.body is None

    def test_missing_header_terminator(self):
        with pytest.raises(ValueError, match="missing header terminator"):
            self._parse(b"GET / HTTP/1.1\r\nHost: example.com")

    def test_malformed_request_line(self):
        with pytest.raises(ValueError, match="malformed HTTP/1.1 request line"):
            self._parse(b"GETONLY\r\n\r\n")

    def test_unsupported_http_version(self):
        with pytest.raises(ValueError, match="unsupported HTTP version"):
            self._parse(b"GET / HTTP/1.0\r\n\r\n")

    def test_both_te_and_content_length(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        with pytest.raises(ValueError):
            self._parse(raw)

    def test_max_body_size_enforced_content_length(self):
        body = b"x" * 100
        raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n" + body
        with pytest.raises(ValueError, match="max_body_size"):
            self._parse(raw, max_body_size=50)

    def test_max_body_size_enforced_chunked(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"64\r\n" + b"x" * 100 + b"\r\n"
            b"0\r\n\r\n"
        )
        with pytest.raises(ValueError, match="max_body_size"):
            self._parse(raw, max_body_size=50)

    def test_tls_info_propagated(self):
        from kaede.tls import TLSInfo
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        tls = TLSInfo(version="TLSv1.3", group=None, cipher=None)
        req = self._parse(raw, tls=tls)
        assert req.tls is tls

    def test_scheme_propagated(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = self._parse(raw, scheme="https", secure=True)
        assert req.scheme == "https"
        assert req.secure is True

    def test_multiple_headers_same_name(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n"
        req = self._parse(raw)
        assert "text/html" in req.headers.get("Accept")
        assert "application/json" in req.headers.get("Accept")

class TestH1BuildResponse:
    def test_200_ok(self):
        r = Response(body=b"hello", status_code=200)
        r.headers.set("Content-Type", "text/plain")
        r.headers.set("Content-Length", "5")
        result = H1.build_response(r)
        assert isinstance(result, bytes)
        assert b"HTTP/1.1 200 OK" in result
        assert b"hello" in result

    def test_404_not_found(self):
        r = Response(body=b"not found", status_code=404)
        result = H1.build_response(r)
        assert b"HTTP/1.1 404 Not Found" in result

    def test_no_body_returns_tuple(self):
        r = Response(body=None, status_code=204)
        result = H1.build_response(r)
        assert isinstance(result, tuple)
        head, body = result
        assert b"HTTP/1.1 204" in head
        assert body is None

    def test_header_injection_filtered(self):
        r = Response(body=b"ok", status_code=200)
        r.headers.set("X-Evil", "value\r\nInjected: header")
        head = H1.build_response_head(r)
        assert b"Injected" not in head

    def test_unknown_status_code(self):
        r = Response(body=b"", status_code=999)
        head = H1.build_response_head(r)
        assert b"HTTP/1.1 999" in head

class TestH1BuildRequest:
    def test_basic_get(self):
        r = Request(method="GET", target="/path")
        r.headers.set("Host", "example.com")
        result = H1.build_request(r)
        assert b"GET /path HTTP/1.1\r\n" in result
        assert b"host: example.com\r\n" in result

    def test_post_with_body(self):
        r = Request(method="POST", target="/api", body=b"data")
        result = H1.build_request(r)
        assert b"POST /api HTTP/1.1\r\n" in result
        assert b"data" in result

class TestH1ParseResponse:
    def test_200_with_body(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        resp = H1.parse_response(raw)
        assert resp.status_code == 200
        assert resp.body == b"hello"

    def test_204_no_content(self):
        raw = b"HTTP/1.1 204 No Content\r\n\r\n"
        resp = H1.parse_response(raw)
        assert resp.status_code == 204
        assert resp.body is None

    def test_head_method_no_body(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        resp = H1.parse_response(raw, method="HEAD")
        assert resp.body is None

    def test_chunked_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        resp = H1.parse_response(raw)
        assert resp.body == b"hello"

    def test_incomplete_response(self):
        with pytest.raises(ValueError, match="missing header terminator"):
            H1.parse_response(b"HTTP/1.1 200 OK")

class TestH1DecodeChunked:
    def test_basic(self):
        data = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        result = H1.decode_chunked(data)
        assert result == b"hello world"

    def test_single_chunk(self):
        data = b"3\r\nabc\r\n0\r\n\r\n"
        assert H1.decode_chunked(data) == b"abc"

    def test_incomplete_returns_none(self):
        result = H1.scan_chunked(b"5\r\nhell")
        assert result is None

    def test_invalid_chunk_size(self):
        with pytest.raises(ValueError, match="invalid chunk size"):
            H1.decode_chunked(b"XY\r\nhello\r\n0\r\n\r\n")

    def test_missing_crlf_terminator(self):
        with pytest.raises(ValueError, match="missing CRLF terminator"):
            H1.decode_chunked(b"5\r\nhelloXX0\r\n\r\n")

class TestH1ResponseHasNoBody:
    @pytest.mark.parametrize("status,method,expected", [
        (200, "HEAD", True),
        (204, "GET", True),
        (304, "GET", True),
        (100, "GET", True),
        (199, "GET", True),
        (101, "GET", True),
        (200, "GET", False),
        (201, "POST", False),
        (205, "GET", True),
        (301, "GET", False),
        (200, "head", True),
    ])

    def test(self, status, method, expected):
        assert H1.response_has_no_body(status, method) is expected

class TestH1ParseRequest2:
    def _parse(self, raw, **kwargs):
        return H1.parse_request(raw, client=CLIENT, **kwargs)

    def test_zero_content_length_body_is_none(self):
        raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
        req = self._parse(raw)
        assert req.body is None

    def test_content_length_truncates_excess_data(self):
        raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nhelloXXXX"
        req = self._parse(raw)
        assert req.body == b"hel"

    def test_folded_header_raises(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n folded-continuation\r\n\r\n"
        with pytest.raises(ValueError):
            self._parse(raw)

    def test_invalid_transfer_encoding_not_chunked(self):
        raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n"
        with pytest.raises(ValueError):
            self._parse(raw)

    def test_transfer_encoding_trailing_chunked_is_valid(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: gzip, chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        req = self._parse(raw)
        assert req.body == b"hello"

    def test_duplicate_chunked_in_te_raises(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked, chunked\r\n"
            b"\r\n"
            b"0\r\n\r\n"
        )
        with pytest.raises(ValueError):
            self._parse(raw)

    def test_options_method(self):
        raw = b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = self._parse(raw)
        assert req.method == "OPTIONS"
        assert req.target == "*"

    def test_target_with_query_string(self):
        raw = b"GET /search?q=hello&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = self._parse(raw)
        assert req.target == "/search?q=hello&lang=en"

    def test_empty_header_value_allowed(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Empty: \r\n\r\n"
        req = self._parse(raw)
        assert req.headers.get("X-Empty") == ""

    def test_header_without_colon_raises(self):
        raw = b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n"
        with pytest.raises(ValueError):
            self._parse(raw)

    def test_large_chunked_body(self):
        chunk_size = 10000
        chunk_data = b"x" * chunk_size
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            + f"{chunk_size:x}\r\n".encode()
            + chunk_data + b"\r\n"
            + b"0\r\n\r\n"
        )
        req = self._parse(raw)
        assert req.body == chunk_data

    def test_ipv6_client_propagated(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        addr = (ipaddress.IPv6Address("::1"), 9000)
        req = H1.parse_request(raw, client=addr)
        assert req.client == addr

class TestH1BuildResponse2:
    def test_streaming_body_returns_tuple(self):
        async def gen():
            yield b"chunk"
        r = Response(body=gen(), status_code=200)
        result = H1.build_response(r)
        assert isinstance(result, tuple)
        head, body = result
        assert b"HTTP/1.1 200" in head
        assert body is not None

    def test_null_byte_in_header_name_filtered(self):
        r = Response(body=b"ok", status_code=200)
        r.headers.set("X-\x00Evil", "value")
        head = H1.build_response_head(r)
        assert b"X-\x00Evil" not in head

    def test_null_byte_in_header_value_filtered(self):
        r = Response(body=b"ok", status_code=200)
        r.headers.set("X-Header", "val\x00ue")
        head = H1.build_response_head(r)
        assert b"val\x00ue" not in head

    def test_custom_header_in_output(self):
        r = Response(body=b"hello", status_code=200)
        r.headers.set("X-Request-Id", "abc123")
        result = H1.build_response(r)
        assert b"x-request-id: abc123" in result

    def test_204_has_no_phrase_body(self):
        r = Response(body=None, status_code=204)
        head, body = H1.build_response(r)
        assert b"204 No Content" in head
        assert body is None

    def test_response_with_multiple_headers(self):
        r = Response(body=b"data", status_code=200)
        r.headers.set("Content-Type", "application/json")
        r.headers.set("Cache-Control", "no-cache")
        result = H1.build_response(r)
        assert b"content-type: application/json" in result
        assert b"cache-control: no-cache" in result

class TestH1BuildRequest2:
    def test_no_body_request(self):
        r = Request(method="GET", target="/index.html")
        result = H1.build_request(r)
        assert b"GET /index.html HTTP/1.1\r\n" in result
        assert result.endswith(b"\r\n")

    def test_header_injection_in_key_filtered(self):
        r = Request(method="GET", target="/")
        r.headers.set("X-\r\nEvil", "value")
        head = H1.build_request_head(r)
        assert b"Evil" not in head

    def test_header_injection_in_value_filtered(self):
        r = Request(method="GET", target="/")
        r.headers.set("X-Test", "value\r\nInjected: yes")
        head = H1.build_request_head(r)
        assert b"Injected" not in head

    def test_delete_method(self):
        r = Request(method="DELETE", target="/resource/1")
        result = H1.build_request(r)
        assert b"DELETE /resource/1 HTTP/1.1\r\n" in result

class TestH1ParseResponse2:
    def test_no_content_length_reads_rest(self):
        raw = b"HTTP/1.1 200 OK\r\n\r\nhello world"
        resp = H1.parse_response(raw)
        assert resp.body == b"hello world"

    def test_empty_body_no_content_length(self):
        raw = b"HTTP/1.1 200 OK\r\n\r\n"
        resp = H1.parse_response(raw)
        assert resp.body is None

    def test_chunked_with_trailer_fields(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n"
            b"X-Trailer: value\r\n"
            b"\r\n"
        )
        resp = H1.parse_response(raw)
        assert resp.body == b"hello"

    def test_max_body_size_content_length_response(self):
        body = b"x" * 200
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n" + body
        with pytest.raises(ValueError, match="max_body_size"):
            H1.parse_response(raw, max_body_size=100)

    def test_max_body_size_chunked_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"c8\r\n" + b"x" * 200 + b"\r\n"
            b"0\r\n\r\n"
        )
        with pytest.raises(ValueError, match="max_body_size"):
            H1.parse_response(raw, max_body_size=100)

    def test_invalid_content_length_string(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nbody"
        with pytest.raises(ValueError, match="invalid Content-Length"):
            H1.parse_response(raw)

    def test_invalid_transfer_encoding_response(self):
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n"
        with pytest.raises(ValueError, match="invalid Transfer-Encoding"):
            H1.parse_response(raw)

    def test_204_ignores_content_length(self):
        raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\nBODYDATA!!"
        resp = H1.parse_response(raw)
        assert resp.status_code == 204
        assert resp.body is None

    def test_status_code_propagated(self):
        raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"
        resp = H1.parse_response(raw)
        assert resp.status_code == 301

    def test_protocol_is_h11(self):
        raw = b"HTTP/1.1 200 OK\r\n\r\n"
        resp = H1.parse_response(raw)
        assert resp.protocol == "HTTP/1.1"

class TestH1ParseResponseHead:
    def test_basic(self):
        status, phrase, headers = H1.parse_response_head(b"HTTP/1.1 200 OK\r\nX-Foo: bar")
        assert status == 200
        assert phrase == "OK"
        assert headers.get("X-Foo") == "bar"

    def test_no_phrase(self):
        status, phrase, headers = H1.parse_response_head(b"HTTP/1.1 200")
        assert status == 200
        assert phrase == ""

    def test_wrong_version_raises(self):
        with pytest.raises(ValueError, match="unsupported HTTP version"):
            H1.parse_response_head(b"HTTP/2.0 200 OK")

    def test_invalid_status_non_digit_raises(self):
        with pytest.raises(ValueError, match="invalid HTTP status code"):
            H1.parse_response_head(b"HTTP/1.1 ABC OK")

    def test_malformed_status_line_raises(self):
        with pytest.raises(ValueError, match="malformed HTTP/1.1 status line"):
            H1.parse_response_head(b"HTTP/1.1")

    def test_empty_status_line_raises(self):
        with pytest.raises(ValueError, match="empty HTTP/1.1 status line"):
            H1.parse_response_head(b"")

    def test_multiple_headers(self):
        head = b"HTTP/1.1 200 OK\r\nA: 1\r\nB: 2"
        _, _, headers = H1.parse_response_head(head)
        assert headers.get("A") == "1"
        assert headers.get("B") == "2"

class TestH1ScanChunked:
    def test_negative_chunk_size_raises(self):
        with pytest.raises(ValueError, match="negative chunk size"):
            H1.scan_chunked(b"-1\r\nhello\r\n0\r\n\r\n")

    def test_trailer_with_fields_skipped(self):
        data = (
            b"5\r\nhello\r\n"
            b"0\r\n"
            b"X-Trailer: ignored\r\n"
            b"\r\n"
        )
        result = H1.scan_chunked(data)
        assert result is not None
        body, consumed = result
        assert body == b"hello"

    def test_incomplete_after_chunk_data_returns_none(self):
        result = H1.scan_chunked(b"5\r\nhell")
        assert result is None

    def test_incomplete_trailer_returns_none(self):
        result = H1.scan_chunked(b"5\r\nhello\r\n0\r\nX-Trailer: val")
        assert result is None

    def test_multiple_chunks_assembled(self):
        data = b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
        result = H1.scan_chunked(data)
        assert result is not None
        body, _ = result
        assert body == b"abcdef"

    def test_all_empty_chunks_body_is_none(self):
        result = H1.scan_chunked(b"0\r\n\r\n")
        assert result is not None
        body, _ = result
        assert body is None

    def test_consumed_offset_correct(self):
        data = b"3\r\nabc\r\n0\r\n\r\nEXTRA"
        result = H1.scan_chunked(data)
        assert result is not None
        body, consumed = result
        assert body == b"abc"
        assert data[consumed:] == b"EXTRA"

    def test_chunk_size_with_hex_uppercase(self):
        data = b"A\r\n" + b"x" * 10 + b"\r\n0\r\n\r\n"
        result = H1.scan_chunked(data)
        assert result is not None
        body, _ = result
        assert body == b"x" * 10
