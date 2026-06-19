"""
End-to-end HTTP/3 request/response over the in-process loopback harness
(real QUIC-TLS handshake, QPACK, framing, and the server request pipeline).

RFC 9114 (HTTP/3), RFC 9110 (HTTP Semantics), RFC 9220 (WebSocket over HTTP/3).
"""
from __future__ import annotations

import os
import asyncio

from kaede.models import Response, Headers, Callback


# ─────────────────────────────────────────────────────────
# Shared callbacks
# ─────────────────────────────────────────────────────────

class EchoCallback(Callback):
    async def on_request(self, request):
        if request.target == "/404":
            return Response(b"not found", status_code=404, content_type="text/plain")
        if request.target == "/500":
            return Response(b"error", status_code=500, content_type="text/plain")
        if request.method == "POST":
            return Response(b"got:" + (request.body or b""), content_type="text/plain")
        if request.method == "HEAD":
            return Response(None, status_code=200, headers=Headers({"Content-Length": "8"}))
        return Response(b"hello h3", content_type="text/plain")


# ─────────────────────────────────────────────────────────
# RFC 9114 §4 / RFC 9110 §9: Basic request–response
# ─────────────────────────────────────────────────────────

class TestRequestResponse:
    async def test_get(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"hello h3"

    async def test_post_with_body(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("POST", "/submit", body=b"payload")
        assert resp.status_code == 200
        assert resp.body == b"got:payload"

    async def test_post_empty_body(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("POST", "/submit", body=b"")
        assert resp.status_code == 200
        assert resp.body == b"got:"

    async def test_put(self, h3_loopback):
        class PutCallback(Callback):
            async def on_request(self, request):
                return Response(b"put:" + (request.body or b""), content_type="text/plain")

        lb = h3_loopback(PutCallback())
        await lb.handshake()
        resp = await lb.request("PUT", "/resource", body=b"data")
        assert resp.status_code == 200
        assert resp.body == b"put:data"

    async def test_delete(self, h3_loopback):
        class DeleteCallback(Callback):
            async def on_request(self, request):
                return Response(b"deleted", content_type="text/plain")

        lb = h3_loopback(DeleteCallback())
        await lb.handshake()
        resp = await lb.request("DELETE", "/item/1")
        assert resp.status_code == 200
        assert resp.body == b"deleted"

    async def test_headers_round_trip(self, h3_loopback):
        class HeaderCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", headers=Headers({"X-Custom": "v1"}), content_type="text/plain")

        lb = h3_loopback(HeaderCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.headers.get("x-custom") == "v1"

    async def test_response_protocol_is_http3(self, h3_loopback):
        """RFC 9114 §4: responses delivered over HTTP/3 MUST be labeled HTTP/3.0."""
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.protocol == "HTTP/3.0"


# ─────────────────────────────────────────────────────────
# RFC 9110 §9.3.2: HEAD
# ─────────────────────────────────────────────────────────

class TestHEADRequest:

    async def test_head_no_body(self, h3_loopback):
        """RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body."""
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("HEAD", "/")
        assert resp.status_code == 200
        assert not resp.body


# ─────────────────────────────────────────────────────────
# RFC 9110 §15: Error status codes
# ─────────────────────────────────────────────────────────

class TestErrorResponses:

    async def test_404(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/404")
        assert resp.status_code == 404

    async def test_500(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/500")
        assert resp.status_code == 500

    async def test_callback_exception_returns_500(self, h3_loopback):
        """An unhandled exception in the callback MUST produce a 500 response."""
        class BrokenCallback(Callback):
            async def on_request(self, request):
                raise RuntimeError("intentional test error")

        lb = h3_loopback(BrokenCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 500

    async def test_various_status_codes(self, h3_loopback):
        for code in (201, 204, 301, 400, 401, 403):
            class StatusCallback(Callback):
                _code = code
                async def on_request(self, request):
                    return Response(None if self._code in (204,) else b"", status_code=self._code)

            lb = h3_loopback(StatusCallback())
            await lb.handshake()
            resp = await lb.request("GET", "/")
            assert resp.status_code == code


# ─────────────────────────────────────────────────────────
# RFC 9114 §6.1 / RFC 9113: Multiplexing (concurrent QUIC streams)
# ─────────────────────────────────────────────────────────

class TestConcurrentRequests:

    async def test_five_concurrent_requests(self, h3_loopback):
        """RFC 9114 §6.1: independent HTTP/3 streams MUST be processed concurrently."""
        class PathCallback(Callback):
            async def on_request(self, request):
                return Response(request.target.encode(), content_type="text/plain")

        lb = h3_loopback(PathCallback())
        await lb.handshake()

        paths = [f"/stream/{i}" for i in range(5)]
        tasks = [asyncio.ensure_future(lb.client_h3.request(
            __import__("kaede.models", fromlist=["Request", "Headers"]).Request(
                method="GET", target=path,
                headers=__import__("kaede.models", fromlist=["Headers"]).Headers({}),
                scheme="https", secure=True, protocol="HTTP/3.0",
            ),
            streaming=False,
        )) for path in paths]

        await lb._pump_until(lambda: all(t.done() for t in tasks), max_iters=400)

        responses = [t.result() for t in tasks]
        for path, resp in zip(paths, responses):
            assert resp.status_code == 200
            assert resp.body == path.encode()

    async def test_ten_sequential_requests_body_integrity(self, h3_loopback):
        """Ten sequential requests on the same QUIC connection must not corrupt bodies."""
        lb = h3_loopback(EchoCallback())
        await lb.handshake()

        for i in range(10):
            resp = await lb.request("POST", f"/req/{i}", body=f"body-{i}".encode())
            assert resp.status_code == 200
            assert resp.body == f"got:body-{i}".encode()


# ─────────────────────────────────────────────────────────
# RFC 9110 §6.4 / RFC 9114 §4.1: Large bodies
# ─────────────────────────────────────────────────────────

class TestLargeBody:

    async def test_large_request_body(self, h3_loopback):
        """Large request body must arrive at the server in full via QUIC DATA frames."""
        class EchoBodyCallback(Callback):
            async def on_request(self, request):
                return Response(request.body or b"", content_type="application/octet-stream")

        payload = os.urandom(256 * 1024)
        lb = h3_loopback(EchoBodyCallback())
        await lb.handshake()
        resp = await lb.request("POST", "/", body=payload)
        assert resp.status_code == 200
        assert resp.body == payload

    async def test_large_response_body(self, h3_loopback):
        """Large response body must be fully received by the client via QUIC DATA frames."""
        payload = os.urandom(256 * 1024)

        class LargeRespCallback(Callback):
            async def on_request(self, request):
                return Response(payload, content_type="application/octet-stream")

        lb = h3_loopback(LargeRespCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert resp.body == payload


# ─────────────────────────────────────────────────────────
# RFC 9114 §4.1 / RFC 9204: Header handling via QPACK
# ─────────────────────────────────────────────────────────

class TestHeaders:

    async def test_multiple_custom_headers(self, h3_loopback):
        """Multiple response headers must survive QPACK encode/decode."""
        class MultiHdrCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", content_type="text/plain", headers=Headers({
                    "X-One": "one", "X-Two": "two", "X-Three": "three",
                }))

        lb = h3_loopback(MultiHdrCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.headers.get("x-one") == "one"
        assert resp.headers.get("x-two") == "two"
        assert resp.headers.get("x-three") == "three"

    async def test_request_header_reaches_callback(self, h3_loopback):
        """Custom request headers must reach the callback after QPACK decode."""
        class ReqHdrCallback(Callback):
            async def on_request(self, request):
                val = request.headers.get("X-Test") or ""
                return Response(val.encode(), content_type="text/plain")

        from kaede.models import Request, Headers as Hdrs
        lb = h3_loopback(ReqHdrCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/", headers=Hdrs({"X-Test": "h3-sentinel"}))
        assert resp.body == b"h3-sentinel"

    async def test_response_header_names_lowercase(self, h3_loopback):
        """RFC 9114 §4.1.2: HTTP/3 header field names MUST be lowercase."""
        class UpperHdrCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", content_type="text/plain",
                                headers=Headers({"X-Upper": "value"}))

        lb = h3_loopback(UpperHdrCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        for key, _ in resp.headers.items():
            assert key == key.lower(), f"Header name not lowercase: {key!r}"


# ─────────────────────────────────────────────────────────
# RFC 9114 §4.2: Streaming response (DATA frames)
# ─────────────────────────────────────────────────────────

class TestStreamingResponse:

    async def test_streaming_chunks_reassembled(self, h3_loopback):
        """A streaming (async generator) response must be sent as DATA frames and
        reassembled by the client into the original byte sequence."""
        async def body():
            for chunk in [b"h3-a", b"h3-b", b"h3-c"]:
                yield chunk
                await asyncio.sleep(0)

        class StreamCallback(Callback):
            async def on_request(self, request):
                return Response(body(), content_type="text/plain")

        lb = h3_loopback(StreamCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/stream")
        assert resp.status_code == 200
        assert resp.body == b"h3-ah3-bh3-c"

    async def test_large_streaming_body(self, h3_loopback):
        """A streaming response split across many QUIC packets must be fully received."""
        chunk_data = os.urandom(32 * 1024)

        async def body():
            for _ in range(8):
                yield chunk_data
                await asyncio.sleep(0)

        class LargeStreamCallback(Callback):
            async def on_request(self, request):
                return Response(body(), content_type="application/octet-stream")

        lb = h3_loopback(LargeStreamCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert resp.body == chunk_data * 8
