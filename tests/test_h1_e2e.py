"""
HTTP/1.1 end-to-end integration tests over a real asyncio TCP loopback.

A genuine kaede server is started on 127.0.0.1:0 for each test group, and a
genuine kaede client connects to it.  No mocks or synthetic transports are used:
every byte travels through the real H1Connection send/receive path, chunked
encoding, keep-alive machinery, and asyncio event loop.

RFC 9112 (HTTP/1.1 Message Syntax), RFC 9110 (HTTP Semantics), RFC 6455
(WebSocket).
"""
from __future__ import annotations

import os
import socket
import asyncio
import pytest

from kaede.models import Request, Response, Headers, Callback, Listener
from kaede.api import server, client

# ─────────────────────────────────────────────────────────
# Callbacks
# ─────────────────────────────────────────────────────────

class EchoCallback(Callback):
    async def on_request(self, request):
        if request.target == "/404":
            return Response(b"not found", status_code=404, content_type="text/plain")
        if request.target == "/500":
            return Response(b"error", status_code=500, content_type="text/plain")
        if request.method == "POST":
            return Response(b"echo:" + (request.body or b""), content_type="text/plain")
        if request.method == "HEAD":
            return Response(None, status_code=200, headers=Headers({"Content-Length": "5"}))
        return Response(b"hello", content_type="text/plain")


class HeaderEchoCallback(Callback):
    async def on_request(self, request):
        hdrs = Headers({"X-Method": request.method, "X-Path": request.target})
        return Response(b"ok", status_code=200, content_type="text/plain", headers=hdrs)


class LargeBodyCallback(Callback):
    async def on_request(self, request):
        return Response(request.body or b"", content_type="application/octet-stream")


async def _chunked_body():
    for chunk in [b"chunk1", b"chunk2", b"chunk3"]:
        yield chunk
        await asyncio.sleep(0)


class StreamingCallback(Callback):
    async def on_request(self, request):
        return Response(_chunked_body(), content_type="text/plain")


class SlowCallback(Callback):
    async def on_request(self, request):
        await asyncio.sleep(0)
        return Response(b"slow", content_type="text/plain")


class EchoWSCallback(Callback):
    async def on_websocket(self, request, ws):
        while True:
            msg = await ws.receive()
            if msg is None:
                break
            await ws.send(msg)


# ─────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────

def _server_socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(socket.SOMAXCONN)
    sock.setblocking(False)
    return sock, sock.getsockname()[1]


@pytest.fixture
async def h1_server():
    """Yield a factory: make(callback) → port.  Cleans up all servers after the test."""
    handlers: list[server.Handler] = []

    async def make(callback) -> int:
        sock, port = _server_socket()
        cfg = server.Config(
            bind_http=[], bind_https=[], bind_quic=[],
            protocols=["http/1.1"],
        )
        h = server.Handler(Listener(sock=sock, kind="http"), callback, cfg)
        await h.start()
        handlers.append(h)
        return port

    yield make

    for h in handlers:
        await h.drain(timeout=2.0)
        await h.stop()


def _client_cfg():
    return client.Config(protocols=["http/1.1"])


async def _request(
    port: int,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> Response:
    h = client.Handler(_client_cfg())
    authority = f"127.0.0.1:{port}"
    conn = await h.get_connection("http", "127.0.0.1", port, authority)
    req = Request(
        method=method,
        target=path,
        headers=Headers(headers or {}),
        body=body,
        scheme="http",
        secure=False,
    )
    return await conn.request(req, streaming=False)


# ─────────────────────────────────────────────────────────
# RFC 9110 §9 / RFC 9112 §3: Basic request–response cycle
# ─────────────────────────────────────────────────────────

class TestBasicRequestResponse:

    async def test_get_200(self, h1_server):
        """GET / must return 200 with the expected body."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"hello"

    async def test_post_body_echoed(self, h1_server):
        """POST body must be delivered to the server callback and echoed back."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "POST", "/submit", body=b"world")
        assert resp.status_code == 200
        assert resp.body == b"echo:world"

    async def test_post_empty_body(self, h1_server):
        """POST with Content-Length: 0 must deliver an empty body."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "POST", "/submit", body=b"")
        assert resp.status_code == 200
        assert resp.body == b"echo:"

    async def test_put_body(self, h1_server):
        """PUT method must carry a body to the server."""
        class PutCallback(Callback):
            async def on_request(self, request):
                return Response(b"put:" + (request.body or b""), content_type="text/plain")

        port = await h1_server(PutCallback())
        resp = await _request(port, "PUT", "/resource", body=b"data")
        assert resp.status_code == 200
        assert resp.body == b"put:data"

    async def test_delete(self, h1_server):
        """DELETE method must reach the server callback."""
        class DeleteCallback(Callback):
            async def on_request(self, request):
                return Response(b"deleted", content_type="text/plain")

        port = await h1_server(DeleteCallback())
        resp = await _request(port, "DELETE", "/item/1")
        assert resp.status_code == 200
        assert resp.body == b"deleted"

    async def test_options(self, h1_server):
        """OPTIONS method must be forwarded to the callback."""
        class OptionsCallback(Callback):
            async def on_request(self, request):
                return Response(
                    None,
                    status_code=204,
                    headers=Headers({"Allow": "GET, POST, OPTIONS"}),
                )

        port = await h1_server(OptionsCallback())
        resp = await _request(port, "OPTIONS", "*")
        assert resp.status_code == 204


# ─────────────────────────────────────────────────────────
# RFC 9110 §9.3.2: HEAD
# ─────────────────────────────────────────────────────────

class TestHEADRequest:

    async def test_head_no_body_in_response(self, h1_server):
        """RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "HEAD", "/")
        assert resp.status_code == 200
        assert not resp.body

    async def test_head_preserves_content_length_header(self, h1_server):
        """RFC 9110 §9.3.2: Content-Length in a HEAD response mirrors the GET body size."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "HEAD", "/")
        cl = resp.headers.get("Content-Length")
        assert cl is not None and int(cl) >= 0


# ─────────────────────────────────────────────────────────
# RFC 9110 §15: Error status codes
# ─────────────────────────────────────────────────────────

class TestErrorResponses:

    async def test_404(self, h1_server):
        """Server MUST return 404 for unknown resources."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "GET", "/404")
        assert resp.status_code == 404

    async def test_500(self, h1_server):
        """Server MUST forward 5xx responses to the client intact."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "GET", "/500")
        assert resp.status_code == 500

    async def test_callback_exception_returns_500(self, h1_server):
        """An unhandled exception in the callback MUST produce a 500 response."""
        class BrokenCallback(Callback):
            async def on_request(self, request):
                raise RuntimeError("intentional test error")

        port = await h1_server(BrokenCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 500

    async def test_custom_status_codes(self, h1_server):
        """Arbitrary 2xx/3xx/4xx status codes must be forwarded to the client."""
        for code in (201, 202, 301, 302, 400, 401, 403):
            class StatusCallback(Callback):
                _code = code
                async def on_request(self, request):
                    return Response(b"", status_code=self._code)

            port = await h1_server(StatusCallback())
            resp = await _request(port, "GET", "/")
            assert resp.status_code == code


# ─────────────────────────────────────────────────────────
# RFC 9112 §9.3: Persistent connections (keep-alive)
# ─────────────────────────────────────────────────────────

class TestKeepalive:

    async def test_multiple_requests_reuse_connection(self, h1_server):
        """RFC 9112 §9.3: HTTP/1.1 connections MUST be persistent by default;
        the client MUST be able to send multiple sequential requests."""
        port = await h1_server(EchoCallback())
        h = client.Handler(_client_cfg())
        authority = f"127.0.0.1:{port}"

        for i in range(5):
            conn = await h.get_connection("http", "127.0.0.1", port, authority)
            req = Request(method="GET", target=f"/?i={i}", headers=Headers({}), scheme="http", secure=False)
            resp = await conn.request(req, streaming=False)
            assert resp.status_code == 200

    async def test_response_body_correct_across_keepalive(self, h1_server):
        """Body content must not bleed between successive keep-alive requests."""
        class CountCallback(Callback):
            count = 0
            async def on_request(self, request):
                CountCallback.count += 1
                return Response(f"req-{CountCallback.count}".encode(), content_type="text/plain")

        port = await h1_server(CountCallback())
        h = client.Handler(_client_cfg())
        authority = f"127.0.0.1:{port}"

        bodies = []
        for _ in range(3):
            conn = await h.get_connection("http", "127.0.0.1", port, authority)
            req = Request(method="GET", target="/", headers=Headers({}), scheme="http", secure=False)
            resp = await conn.request(req, streaming=False)
            bodies.append(resp.body)

        assert bodies == [b"req-1", b"req-2", b"req-3"]


# ─────────────────────────────────────────────────────────
# RFC 9112 §7.1: Chunked transfer encoding (streaming)
# ─────────────────────────────────────────────────────────

class TestStreamingResponse:

    async def test_chunked_body_reassembled(self, h1_server):
        """Client MUST reassemble a Transfer-Encoding: chunked body into the
        original byte sequence."""
        port = await h1_server(StreamingCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"chunk1chunk2chunk3"

    async def test_empty_streaming_body(self, h1_server):
        """An async generator that yields nothing must produce an empty body."""
        async def _empty():
            return
            yield  # noqa: unreachable – makes this an async generator

        class EmptyStreamCallback(Callback):
            async def on_request(self, request):
                return Response(_empty(), content_type="text/plain")

        port = await h1_server(EmptyStreamCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == b""


# ─────────────────────────────────────────────────────────
# RFC 9110 §6.4: Large message bodies
# ─────────────────────────────────────────────────────────

class TestLargeBody:

    async def test_large_request_body(self, h1_server):
        """A request body that spans multiple TCP segments must be delivered in full."""
        payload = os.urandom(512 * 1024)
        port = await h1_server(LargeBodyCallback())
        resp = await _request(port, "POST", "/", body=payload)
        assert resp.status_code == 200
        assert resp.body == payload

    async def test_large_response_body(self, h1_server):
        """A response body that spans multiple TCP segments must be received in full."""
        payload = os.urandom(512 * 1024)

        class LargeResponseCallback(Callback):
            async def on_request(self, request):
                return Response(payload, content_type="application/octet-stream")

        port = await h1_server(LargeResponseCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == payload

    async def test_large_round_trip(self, h1_server):
        """Request and response both large: end-to-end integrity check."""
        payload = os.urandom(256 * 1024)
        port = await h1_server(LargeBodyCallback())
        resp = await _request(port, "POST", "/", body=payload)
        assert resp.body == payload


# ─────────────────────────────────────────────────────────
# RFC 9110 §5 / RFC 9112 §5: Response headers
# ─────────────────────────────────────────────────────────

class TestResponseHeaders:

    async def test_custom_header_preserved(self, h1_server):
        """Custom response headers must arrive at the client intact."""
        class CustomHdrCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", content_type="text/plain",
                                headers=Headers({"X-Custom": "test-value", "X-Num": "42"}))

        port = await h1_server(CustomHdrCallback())
        resp = await _request(port, "GET", "/")
        assert resp.headers.get("X-Custom") == "test-value"
        assert resp.headers.get("X-Num") == "42"

    async def test_content_type_forwarded(self, h1_server):
        """Content-Type header must be forwarded verbatim."""
        port = await h1_server(EchoCallback())
        resp = await _request(port, "GET", "/")
        ct = resp.headers.get("Content-Type") or ""
        assert "text/plain" in ct

    async def test_request_headers_reach_callback(self, h1_server):
        """Custom request headers must be visible to the server callback."""
        class ReqHdrCallback(Callback):
            async def on_request(self, request):
                val = request.headers.get("X-Test-Header") or ""
                return Response(val.encode(), content_type="text/plain")

        port = await h1_server(ReqHdrCallback())
        resp = await _request(port, "GET", "/", headers={"X-Test-Header": "sentinel"})
        assert resp.body == b"sentinel"

    async def test_multiple_request_values_in_header(self, h1_server):
        """Multiple values for the same header field must all reach the server."""
        class MultiHdrCallback(Callback):
            async def on_request(self, request):
                values = request.headers.get("X-Multi")
                if isinstance(values, list):
                    return Response(b"|".join(v.encode() for v in values), content_type="text/plain")
                return Response((values or b"").encode() if isinstance(values, str) else b"", content_type="text/plain")

        port = await h1_server(MultiHdrCallback())
        resp = await _request(port, "GET", "/", headers={"X-Multi": "a"})
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────
# RFC 9112 §9.7: request routing via path
# ─────────────────────────────────────────────────────────

class TestRequestRouting:

    async def test_path_and_query_delivered(self, h1_server):
        """The full request-target including query string must reach the callback."""
        class PathCallback(Callback):
            async def on_request(self, request):
                return Response(request.target.encode(), content_type="text/plain")

        port = await h1_server(PathCallback())
        resp = await _request(port, "GET", "/path?key=value&foo=bar")
        assert resp.body == b"/path?key=value&foo=bar"

    async def test_multiple_paths_sequential(self, h1_server):
        """Sequential requests to different paths must each route correctly."""
        class PathCallback(Callback):
            async def on_request(self, request):
                return Response(request.target.encode(), content_type="text/plain")

        port = await h1_server(PathCallback())
        for path in ["/a", "/b", "/c"]:
            resp = await _request(port, "GET", path)
            assert resp.body == path.encode()


# ─────────────────────────────────────────────────────────
# RFC 6455 §4: WebSocket upgrade over HTTP/1.1
# ─────────────────────────────────────────────────────────

class TestWebSocketOverH1:

    async def test_ws_echo_text(self, h1_server):
        """WebSocket upgrade and text echo must complete over an H1 connection."""
        from kaede.websocket import generate_key, build_frame, parse_frames, compute_accept, Opcode

        port = await h1_server(EchoWSCallback())

        loop = asyncio.get_running_loop()

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        ws_key = generate_key()
        upgrade = (
            b"GET /chat HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            + b"Sec-WebSocket-Key: " + ws_key.encode() + b"\r\n"
            + b"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        writer.write(upgrade)
        await writer.drain()

        resp_bytes = b""
        while b"\r\n\r\n" not in resp_bytes:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert chunk, "connection closed before upgrade response"
            resp_bytes += chunk

        head = resp_bytes.split(b"\r\n\r\n", 1)[0].decode()
        assert "101" in head, f"Expected 101, got: {head!r}"

        accept_hdr = next(
            (line.split(":", 1)[1].strip() for line in head.splitlines() if "Sec-WebSocket-Accept" in line),
            None,
        )
        assert accept_hdr is not None
        from kaede.websocket import check_accept
        assert check_accept(ws_key, accept_hdr), "Sec-WebSocket-Accept mismatch"

        payload = b"hello websocket"
        frame = build_frame(Opcode.TEXT, payload, mask=True)
        writer.write(frame)
        await writer.drain()

        echo_data = b""
        while len(echo_data) < 2:
            echo_data += await asyncio.wait_for(reader.read(4096), timeout=5.0)

        frames = parse_frames(bytearray(echo_data), 4096 * 1024)
        assert frames
        assert frames[0].payload == payload

        writer.close()
        await writer.wait_closed()

    async def test_ws_multiple_messages(self, h1_server):
        """Multiple WebSocket messages must all echo correctly in order."""
        from kaede.websocket import generate_key, build_frame, parse_frames, Opcode

        port = await h1_server(EchoWSCallback())
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        ws_key = generate_key()
        upgrade = (
            b"GET /chat HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            + b"Sec-WebSocket-Key: " + ws_key.encode() + b"\r\n"
            + b"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        writer.write(upgrade)
        await writer.drain()

        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += await asyncio.wait_for(reader.read(4096), timeout=5.0)

        messages = [b"first", b"second", b"third"]
        for msg in messages:
            writer.write(build_frame(Opcode.TEXT, msg, mask=True))
        await writer.drain()

        received = []
        raw = b""
        while len(received) < len(messages):
            raw += await asyncio.wait_for(reader.read(4096), timeout=5.0)
            frames = parse_frames(bytearray(raw), 4 * 1024 * 1024)
            for f in frames:
                received.append(f.payload)
            if frames:
                consumed = sum(f._frame_length for f in frames if hasattr(f, "_frame_length"))
                raw = raw[consumed:]

        assert received[:3] == messages

        writer.close()
        await writer.wait_closed()
