"""
HTTP/2 end-to-end integration tests over a real TLS TCP loopback.

A genuine kaede HTTPS server (HTTP/2 via ALPN) is started on 127.0.0.1:0, and a
genuine kaede client connects with TLS certificate verification disabled.  No
mocks are used: every byte travels through the real H2Connection send/receive
path, HPACK encoding, asyncio event loop, and the custom TLS layer.

RFC 9113 (HTTP/2), RFC 9110 (HTTP Semantics), RFC 8441 (WebSocket over HTTP/2).
"""
from __future__ import annotations

import os
import asyncio
import socket
import pytest

from kaede.models import Request, Response, Headers, Callback, Listener
from kaede.tls.models import TLSServerConfig, TLSClientConfig
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
        return Response(b"hello h2", content_type="text/plain")


class LargeBodyCallback(Callback):
    async def on_request(self, request):
        return Response(request.body or b"", content_type="application/octet-stream")


async def _chunked_body():
    for chunk in [b"h2-chunk1", b"h2-chunk2", b"h2-chunk3"]:
        yield chunk
        await asyncio.sleep(0)


class StreamingCallback(Callback):
    async def on_request(self, request):
        return Response(_chunked_body(), content_type="text/plain")


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
async def h2_server(tls_cert):
    """Yield a factory: make(callback) → port. All servers are cleaned up after the test."""
    certfile, keyfile = tls_cert
    handlers: list[server.Handler] = []

    async def make(callback) -> int:
        sock, port = _server_socket()
        tls = TLSServerConfig(certfile=certfile, keyfile=keyfile)
        cfg = server.Config(
            bind_http=[], bind_https=[], bind_quic=[],
            protocols=["h2"],
            tls=tls,
        )
        h = server.Handler(Listener(sock=sock, kind="https"), callback, cfg)
        await h.start()
        handlers.append(h)
        return port

    yield make

    for h in handlers:
        await h.drain(timeout=2.0)
        await h.stop()


def _client_cfg():
    return client.Config(
        protocols=["h2"],
        tls=TLSClientConfig(verify=False, check_hostname=False),
    )


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
    conn = await h.get_connection("https", "127.0.0.1", port, authority)
    req = Request(
        method=method,
        target=path,
        headers=Headers(headers or {}),
        body=body,
        scheme="https",
        secure=True,
    )
    return await conn.request(req, streaming=False)


# ─────────────────────────────────────────────────────────
# RFC 9113 §8 / RFC 9110 §9: Basic request–response cycle
# ─────────────────────────────────────────────────────────

class TestBasicRequestResponse:

    async def test_get_200(self, h2_server):
        """GET / must return 200 with the expected body over HTTP/2."""
        port = await h2_server(EchoCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"hello h2"

    async def test_post_body_echoed(self, h2_server):
        """POST body must reach the callback and be echoed back via an H2 DATA frame."""
        port = await h2_server(EchoCallback())
        resp = await _request(port, "POST", "/submit", body=b"world")
        assert resp.status_code == 200
        assert resp.body == b"echo:world"

    async def test_post_empty_body(self, h2_server):
        port = await h2_server(EchoCallback())
        resp = await _request(port, "POST", "/submit", body=b"")
        assert resp.status_code == 200
        assert resp.body == b"echo:"

    async def test_put(self, h2_server):
        class PutCallback(Callback):
            async def on_request(self, request):
                return Response(b"put:" + (request.body or b""), content_type="text/plain")

        port = await h2_server(PutCallback())
        resp = await _request(port, "PUT", "/resource", body=b"data")
        assert resp.status_code == 200
        assert resp.body == b"put:data"

    async def test_delete(self, h2_server):
        class DeleteCallback(Callback):
            async def on_request(self, request):
                return Response(b"deleted", content_type="text/plain")

        port = await h2_server(DeleteCallback())
        resp = await _request(port, "DELETE", "/item/1")
        assert resp.status_code == 200
        assert resp.body == b"deleted"

    async def test_response_protocol_is_http2(self, h2_server):
        """RFC 9113 §3.4: responses over HTTP/2 MUST be labeled as HTTP/2.0."""
        port = await h2_server(EchoCallback())
        resp = await _request(port, "GET", "/")
        assert resp.protocol == "HTTP/2.0"


# ─────────────────────────────────────────────────────────
# RFC 9110 §9.3.2: HEAD
# ─────────────────────────────────────────────────────────

class TestHEADRequest:

    async def test_head_no_body(self, h2_server):
        """RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body."""
        port = await h2_server(EchoCallback())
        resp = await _request(port, "HEAD", "/")
        assert resp.status_code == 200
        assert not resp.body


# ─────────────────────────────────────────────────────────
# RFC 9110 §15: Error status codes
# ─────────────────────────────────────────────────────────

class TestErrorResponses:

    async def test_404(self, h2_server):
        port = await h2_server(EchoCallback())
        resp = await _request(port, "GET", "/404")
        assert resp.status_code == 404

    async def test_500(self, h2_server):
        port = await h2_server(EchoCallback())
        resp = await _request(port, "GET", "/500")
        assert resp.status_code == 500

    async def test_callback_exception_returns_500(self, h2_server):
        """An unhandled exception in the callback MUST produce a 500 response."""
        class BrokenCallback(Callback):
            async def on_request(self, request):
                raise RuntimeError("intentional test error")

        port = await h2_server(BrokenCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 500

    async def test_various_status_codes(self, h2_server):
        for code in (201, 204, 301, 400, 401, 403):
            class StatusCallback(Callback):
                _code = code
                async def on_request(self, request):
                    return Response(None if self._code in (204, 304) else b"", status_code=self._code)

            port = await h2_server(StatusCallback())
            resp = await _request(port, "GET", "/")
            assert resp.status_code == code


# ─────────────────────────────────────────────────────────
# RFC 9113 §5: HTTP/2 multiplexing (concurrent streams)
# ─────────────────────────────────────────────────────────

class TestMultiplexing:

    async def test_concurrent_requests_on_same_connection(self, h2_server):
        """RFC 9113 §5: HTTP/2 MUST multiplex independent requests on a single connection."""
        class PathCallback(Callback):
            async def on_request(self, request):
                await asyncio.sleep(0)
                return Response(request.target.encode(), content_type="text/plain")

        port = await h2_server(PathCallback())
        h = client.Handler(_client_cfg())
        authority = f"127.0.0.1:{port}"
        conn = await h.get_connection("https", "127.0.0.1", port, authority)

        paths = [f"/stream/{i}" for i in range(5)]
        tasks = []
        for path in paths:
            req = Request(method="GET", target=path, headers=Headers({}), scheme="https", secure=True)
            tasks.append(asyncio.ensure_future(conn.request(req, streaming=False)))

        responses = await asyncio.gather(*tasks)
        for path, resp in zip(paths, responses):
            assert resp.status_code == 200
            assert resp.body == path.encode()

    async def test_sequential_requests_correct_bodies(self, h2_server):
        """Successive requests on the same H2 connection must receive independent bodies."""
        port = await h2_server(EchoCallback())
        h = client.Handler(_client_cfg())
        authority = f"127.0.0.1:{port}"

        bodies = []
        conn = await h.get_connection("https", "127.0.0.1", port, authority)
        for i in range(4):
            req = Request(method="POST", target="/", headers=Headers({}), body=f"req-{i}".encode(), scheme="https", secure=True)
            resp = await conn.request(req, streaming=False)
            bodies.append(resp.body)

        assert bodies == [f"echo:req-{i}".encode() for i in range(4)]

    async def test_many_concurrent_requests(self, h2_server):
        """Ten concurrent requests must all complete with correct, independent bodies."""
        class EchoBodyCallback(Callback):
            async def on_request(self, request):
                return Response(request.body or b"", content_type="application/octet-stream")

        port = await h2_server(EchoBodyCallback())
        h = client.Handler(_client_cfg())
        authority = f"127.0.0.1:{port}"
        conn = await h.get_connection("https", "127.0.0.1", port, authority)

        payloads = [os.urandom(64) for _ in range(10)]
        tasks = [
            asyncio.ensure_future(
                conn.request(
                    Request(method="POST", target="/", headers=Headers({}), body=p, scheme="https", secure=True),
                    streaming=False,
                )
            )
            for p in payloads
        ]
        responses = await asyncio.gather(*tasks)
        for payload, resp in zip(payloads, responses):
            assert resp.body == payload


# ─────────────────────────────────────────────────────────
# RFC 9110 §6.4: Large message bodies
# ─────────────────────────────────────────────────────────

class TestLargeBody:

    async def test_large_request_body(self, h2_server):
        """A large request body must be split into DATA frames and fully reassembled."""
        payload = os.urandom(512 * 1024)
        port = await h2_server(LargeBodyCallback())
        resp = await _request(port, "POST", "/", body=payload)
        assert resp.status_code == 200
        assert resp.body == payload

    async def test_large_response_body(self, h2_server):
        """A large response body split across DATA frames must be fully received."""
        payload = os.urandom(512 * 1024)

        class LargeRespCallback(Callback):
            async def on_request(self, request):
                return Response(payload, content_type="application/octet-stream")

        port = await h2_server(LargeRespCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == payload

    async def test_large_round_trip(self, h2_server):
        payload = os.urandom(256 * 1024)
        port = await h2_server(LargeBodyCallback())
        resp = await _request(port, "POST", "/", body=payload)
        assert resp.body == payload


# ─────────────────────────────────────────────────────────
# RFC 9113 §8.2 / RFC 9110 §5: Header handling
# ─────────────────────────────────────────────────────────

class TestHeaders:

    async def test_custom_response_header_preserved(self, h2_server):
        """Custom response headers must survive HPACK encode/decode round-trip."""
        class HdrCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", content_type="text/plain",
                                headers=Headers({"X-Custom": "hpack-value"}))

        port = await h2_server(HdrCallback())
        resp = await _request(port, "GET", "/")
        assert resp.headers.get("X-Custom") == "hpack-value"

    async def test_request_header_reaches_callback(self, h2_server):
        """Custom request headers must arrive at the callback after HPACK decode."""
        class ReqHdrCallback(Callback):
            async def on_request(self, request):
                val = request.headers.get("X-Test") or ""
                return Response(val.encode(), content_type="text/plain")

        port = await h2_server(ReqHdrCallback())
        resp = await _request(port, "GET", "/", headers={"X-Test": "h2-sentinel"})
        assert resp.body == b"h2-sentinel"

    async def test_response_header_names_lowercase(self, h2_server):
        """RFC 9113 §8.2: all HTTP/2 header field names MUST be lowercase."""
        class UpperHdrCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", content_type="text/plain",
                                headers=Headers({"X-Upper-Case": "value"}))

        port = await h2_server(UpperHdrCallback())
        resp = await _request(port, "GET", "/")
        for key, _ in resp.headers.items():
            assert key == key.lower(), f"Header name not lowercase: {key!r}"

    async def test_multiple_headers_round_trip(self, h2_server):
        """Multiple distinct response headers must all be delivered."""
        class MultiHdrCallback(Callback):
            async def on_request(self, request):
                hdrs = Headers({
                    "X-One": "one",
                    "X-Two": "two",
                    "X-Three": "three",
                })
                return Response(b"ok", content_type="text/plain", headers=hdrs)

        port = await h2_server(MultiHdrCallback())
        resp = await _request(port, "GET", "/")
        assert resp.headers.get("X-One") == "one"
        assert resp.headers.get("X-Two") == "two"
        assert resp.headers.get("X-Three") == "three"

    async def test_content_type_forwarded(self, h2_server):
        port = await h2_server(EchoCallback())
        resp = await _request(port, "GET", "/")
        ct = resp.headers.get("Content-Type") or ""
        assert "text/plain" in ct


# ─────────────────────────────────────────────────────────
# RFC 9113 §8.4: Response streaming (DATA frames)
# ─────────────────────────────────────────────────────────

class TestStreamingResponse:

    async def test_streaming_chunks_reassembled(self, h2_server):
        """Streaming response chunks must be reassembled by the client in order."""
        port = await h2_server(StreamingCallback())
        resp = await _request(port, "GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"h2-chunk1h2-chunk2h2-chunk3"


# ─────────────────────────────────────────────────────────
# RFC 8441 §4: WebSocket over HTTP/2 (extended CONNECT)
# ─────────────────────────────────────────────────────────

class TestWebSocketOverH2:

    async def test_echo_text_message(self, h2_server):
        """A text message sent over a WebSocket-over-H2 stream must be echoed back."""
        port = await h2_server(EchoWSCallback())
        h = client.Handler(_client_cfg())
        ws = await h.websocket(f"wss://127.0.0.1:{port}/chat", None, None)

        await ws.send("hello h2 ws")
        echo = await asyncio.wait_for(ws.receive(), timeout=5.0)
        assert echo == b"hello h2 ws"
        await ws.close(1000)

    async def test_echo_binary_message(self, h2_server):
        """A binary message must be echoed back as-is over WebSocket-over-H2."""
        port = await h2_server(EchoWSCallback())
        h = client.Handler(_client_cfg())
        ws = await h.websocket(f"wss://127.0.0.1:{port}/chat", None, None)

        payload = b"\x00\x01\x02\x03binary-h2"
        await ws.send(payload)
        echo = await asyncio.wait_for(ws.receive(), timeout=5.0)
        assert echo == payload
        await ws.close(1000)

    async def test_multiple_messages(self, h2_server):
        """Multiple messages over a WebSocket-over-H2 stream must all echo in order."""
        port = await h2_server(EchoWSCallback())
        h = client.Handler(_client_cfg())
        ws = await h.websocket(f"wss://127.0.0.1:{port}/chat", None, None)

        for i in range(5):
            payload = f"msg-h2-{i}".encode()
            await ws.send(payload)
            echo = await asyncio.wait_for(ws.receive(), timeout=5.0)
            assert echo == payload

        await ws.close(1000)

    async def test_subprotocol_negotiation(self, h2_server):
        """RFC 8441 §4: the server MUST negotiate the WebSocket subprotocol."""
        class SubprotoCallback(Callback):
            def __init__(self):
                super().__init__()
                self.websocket_subprotocols = ["chat"]

            async def on_websocket(self, request, ws):
                await ws.send(f"sub={ws.subprotocol or 'none'}".encode())
                await ws.close(1000)

        port = await h2_server(SubprotoCallback())
        h = client.Handler(_client_cfg())
        ws = await h.websocket(f"wss://127.0.0.1:{port}/chat", ["chat"], None)
        assert ws.subprotocol == "chat"
        msg = await asyncio.wait_for(ws.receive(), timeout=5.0)
        assert msg == b"sub=chat"


# ─────────────────────────────────────────────────────────
# RFC 9113 §6.8: SETTINGS frame / flow control
# ─────────────────────────────────────────────────────────

class TestFlowControl:

    async def test_body_larger_than_initial_window(self, h2_server):
        """RFC 9113 §6.9: Data exceeding the initial flow-control window must be
        fully delivered once the receiver sends WINDOW_UPDATE frames."""
        payload = os.urandom(128 * 1024)
        port = await h2_server(LargeBodyCallback())
        resp = await _request(port, "POST", "/", body=payload)
        assert resp.body == payload

    async def test_concurrent_large_requests(self, h2_server):
        """Multiple large concurrent requests must not corrupt each other via
        flow-control interleaving."""
        payloads = [os.urandom(64 * 1024) for _ in range(3)]

        class EchoBodyCallback(Callback):
            async def on_request(self, request):
                return Response(request.body or b"", content_type="application/octet-stream")

        port = await h2_server(EchoBodyCallback())
        h = client.Handler(_client_cfg())
        authority = f"127.0.0.1:{port}"
        conn = await h.get_connection("https", "127.0.0.1", port, authority)

        tasks = [
            asyncio.ensure_future(
                conn.request(
                    Request(method="POST", target="/", headers=Headers({}), body=p, scheme="https", secure=True),
                    streaming=False,
                )
            )
            for p in payloads
        ]
        responses = await asyncio.gather(*tasks)
        for payload, resp in zip(payloads, responses):
            assert resp.body == payload
