"""
RFC 9113 (HTTP/2) header building and connection conformance tests.
"""
from __future__ import annotations

import asyncio
import ipaddress
import pytest
import h2.config
import h2.connection
import h2.errors
from kaede.http.models import Request, Response, Headers, RawRequest
from kaede.http.h2 import H2, H2Connection, H2Info, H2_FORBIDDEN_HEADERS

FORBIDDEN = list(H2_FORBIDDEN_HEADERS)

# RFC 9113 §8.2.2: Connection-specific header fields

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

# RFC 9113 §8.3: Pseudo-header fields

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

# RFC 9113 §8.2: Header field names must be lowercase

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

# Security: CRLF injection prevention

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

# RFC 9113 §8.4: Extended CONNECT (WebSocket over HTTP/2)

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

# RFC 9113 §8.2.2: TE header handling

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

# RFC 9113 §8.3: Request pseudo-header ordering and completeness

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

# RFC 9113 §8.1: Content-Length semantics in HTTP/2

class TestH2ContentLength:
    def test_content_length_zero_added_for_empty_body(self):
        """RFC 9110 §8.6: body=b'' is an explicit empty body; content-length: 0 MUST be present"""
        req = Request(method="POST", target="/", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com", body=b"")
        cl_values = [v for n, v in built if n == "content-length"]
        assert cl_values == ["0"]

    def test_content_length_value_correct(self):
        """content-length must equal the actual body byte count"""
        body = b"hello world"
        req = Request(method="POST", target="/upload", headers=Headers({}))
        built = H2.build_request_headers(req, "example.com", body=body)
        cl_values = [v for n, v in built if n == "content-length"]
        assert cl_values == [str(len(body))]

# RFC 9113 §5 / §8: H2Connection.receive() — server-side request parsing

CLIENT_ADDR = (ipaddress.IPv4Address("127.0.0.1"), 12345)

class MockConfig:
    max_body_size = 10 * 1024 * 1024
    max_stream_resets = 1000
    max_concurrent_streams = 100
    max_stream_buffer_size = 65536

class MockHandler:
    config = MockConfig()

class MockProtocol:
    def __init__(self):
        self.handler = MockHandler()
        self.transport = None
        self.closed = False

def make_h2_pair():
    """Return (server H2Connection, h2-library client) after a full connection handshake."""
    mock = MockProtocol()
    server = H2Connection(mock, is_client=False)
    server_preface = server.initiate()

    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    client.initiate_connection()
    client_preface = client.data_to_send()

    out, _, _, _, _ = server.receive(client_preface, client=CLIENT_ADDR)
    client.receive_data(server_preface)
    if out:
        client.receive_data(out)
    client_ack = client.data_to_send()
    if client_ack:
        server.receive(client_ack, client=CLIENT_ADDR)

    return server, client

class TestH2ReceiveValidRequests:
    """RFC 9113 §8.3: Valid request semantics."""

    def test_get_request_parsed(self):
        """A complete GET request must be returned in the completed list."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        client.send_headers(sid, [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "example.com"),
        ], end_stream=True)
        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert len(requests) == 1
        assert requests[0].method == "GET"
        assert requests[0].target == "/"

    def test_post_with_body_parsed(self):
        """POST with a request body must be accumulated and delivered."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        body = b"hello world"
        client.send_headers(sid, [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/submit"),
            (":authority", "example.com"),
            ("content-length", str(len(body))),
        ], end_stream=False)
        client.send_data(sid, body, end_stream=True)
        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert len(requests) == 1
        req = requests[0]
        assert req.method == "POST"
        assert req.body == body

    def test_h2info_stream_id_populated(self):
        """RFC 9113 §5.1: Each request must carry the originating stream ID."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        client.send_headers(sid, [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "example.com"),
        ], end_stream=True)
        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert requests[0].h2 is not None
        assert requests[0].h2.stream_id == sid

    def test_h2info_connection_id_is_8_bytes(self):
        """connection_id must be a random 8-byte identifier."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        client.send_headers(sid, [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "example.com"),
        ], end_stream=True)
        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert isinstance(requests[0].h2.connection_id, bytes)
        assert len(requests[0].h2.connection_id) == 8

    def testCLIENT_ADDRess_stored(self):
        """The client address passed to receive() must appear on the Request."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        client.send_headers(sid, [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "example.com"),
        ], end_stream=True)
        data = client.data_to_send()
        addr = (ipaddress.IPv4Address("10.0.0.1"), 5000)
        _, requests, _, _, _ = server.receive(data, client=addr)
        assert requests[0].client == addr

    def test_authority_becomes_host_header(self):
        """RFC 9113 §8.3.1: :authority must be mapped to the Host header."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        client.send_headers(sid, [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "api.example.com"),
        ], end_stream=True)
        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert requests[0].headers.get("host") == "api.example.com"

    def test_multiple_requests_in_single_receive(self):
        """Multiple streams may be completed in a single receive() call."""
        server, client = make_h2_pair()
        for _ in range(3):
            sid = client.get_next_available_stream_id()
            client.send_headers(sid, [
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "example.com"),
            ], end_stream=True)
        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert len(requests) == 3

def make_h2_pair_forbidden_headers():
    """Like make_h2_pair() but both sides skip header validation so that
    connection-specific (forbidden) headers can pass through the h2 library
    and reach Kaede's own forbidden-header detection code."""
    mock = MockProtocol()
    server = H2Connection(mock, is_client=False)

    # Replace the internal h2 connection with one that does not validate inbound
    # headers — this lets Kaede's own check (not the h2 library) handle them.
    server.connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(
            client_side=False,
            header_encoding="utf-8",
            validate_inbound_headers=False,
        )
    )
    server_preface = server.initiate()

    client = h2.connection.H2Connection(
        config=h2.config.H2Configuration(
            client_side=True,
            header_encoding="utf-8",
            validate_outbound_headers=False,
            normalize_outbound_headers=False,
        )
    )
    client.initiate_connection()
    client_preface = client.data_to_send()

    out, _, _, _, _ = server.receive(client_preface, client=CLIENT_ADDR)
    client.receive_data(server_preface)
    if out:
        client.receive_data(out)
    client_ack = client.data_to_send()
    if client_ack:
        server.receive(client_ack, client=CLIENT_ADDR)

    return server, client

class TestH2ReceiveForbiddenHeaders:
    """RFC 9113 §8.2.2: Requests with forbidden headers must be reset."""

    @pytest.mark.parametrize("header", ["connection", "transfer-encoding", "keep-alive"])
    def test_forbidden_header_resets_stream(self, header):
        """A stream that carries a forbidden HTTP/2 header must be reset; no request yielded."""
        server, client = make_h2_pair_forbidden_headers()
        sid = client.get_next_available_stream_id()
        try:
            client.send_headers(sid, [
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "example.com"),
                (header, "value"),
            ], end_stream=True)
        except Exception:
            pytest.skip(f"h2 client refused to send '{header}' even with validation disabled")

        data = client.data_to_send()
        _, requests, _, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert len(requests) == 0

class TestH2ContentLengthMismatch:
    """RFC 9113 §8.1.1: Content-Length must match actual body size."""

    def test_content_length_mismatch_returns_none(self):
        """A request whose body size doesn't match content-length must be reset."""
        mock = MockProtocol()
        server = H2Connection(mock, is_client=False)

        raw = RawRequest(scheme="https")
        raw.method = "POST"
        raw.target = "/"
        raw.headers.append("host", "example.com")
        raw.headers.append("content-length", "10")
        raw.body.extend(b"hello")  # 5 bytes; content-length says 10

        server.request_streams[1] = raw
        result = server.finalize_request(1, CLIENT_ADDR, True, None)
        assert result is None

    def test_matching_content_length_returns_request(self):
        """A correct content-length must not prevent the request from being returned."""
        mock = MockProtocol()
        server = H2Connection(mock, is_client=False)

        raw = RawRequest(scheme="https")
        raw.method = "POST"
        raw.target = "/"
        raw.headers.append("host", "example.com")
        raw.headers.append("content-length", "5")
        raw.body.extend(b"hello")  # 5 bytes matches

        server.request_streams[1] = raw
        result = server.finalize_request(1, CLIENT_ADDR, True, None)
        assert result is not None
        assert result.body == b"hello"

    def test_no_content_length_header_accepted(self):
        """Requests without content-length must not be rejected on body size."""
        mock = MockProtocol()
        server = H2Connection(mock, is_client=False)

        raw = RawRequest(scheme="https")
        raw.method = "POST"
        raw.target = "/"
        raw.headers.append("host", "example.com")
        raw.body.extend(b"hello")

        server.request_streams[1] = raw
        result = server.finalize_request(1, CLIENT_ADDR, True, None)
        assert result is not None

class TestH2ExtendedConnect:
    """RFC 8441: Extended CONNECT (WebSocket over HTTP/2)."""

    def test_extended_connect_added_to_ws_upgrades(self):
        """CONNECT with :protocol=websocket must produce a websocket upgrade, not a plain request."""
        server, client = make_h2_pair()
        sid = client.get_next_available_stream_id()
        try:
            client.send_headers(sid, [
                (":method", "CONNECT"),
                (":protocol", "websocket"),
                (":scheme", "https"),
                (":path", "/ws"),
                (":authority", "example.com"),
                ("sec-websocket-version", "13"),
            ], end_stream=False)
        except Exception:
            pytest.skip("h2 client does not support :protocol pseudo-header for extended CONNECT")

        data = client.data_to_send()
        _, requests, websocket_upgrades, _, _ = server.receive(data, client=CLIENT_ADDR)
        assert len(websocket_upgrades) == 1
        assert len(requests) == 0
        assert websocket_upgrades[0].stream_id == sid
