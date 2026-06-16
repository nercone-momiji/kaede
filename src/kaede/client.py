from __future__ import annotations

import ssl
import asyncio
from typing import Literal, AsyncIterator
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from importlib.metadata import version

from aioquic.asyncio import connect as quic_connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

from .h1 import H1
from .h2 import H2
from .h3 import H3
from .tls import TLS, TLSClientConfig
from .models import Request, Response, Headers
from .process import process_response, wrap_streaming_response
from .websocket import WebSocket, parse_frames, generate_key, check_accept

MAX_RESPONSE_HEADER_SIZE = 64 * 1024

@dataclass
class Config:
    user_agent: str = f"Kaede/{version('nercone-kaede')} (+https://github.com/nercone-momiji/kaede/)"

    protocols: list[Literal["http/1.1", "h2", "h3"]] = field(default_factory=lambda: ["h3", "h2", "http/1.1"])

    tls: TLSClientConfig = field(default_factory=lambda: TLSClientConfig())

    connect_timeout: float = 30
    read_timeout: float = 60

    max_body_size: int = 16 * 1024 * 1024
    max_concurrent_streams: int = 100
    max_websocket_message_size: int = 4 * 1024 * 1024

    max_connections_per_host: int = 10

    decompress: bool = True

class StreamState:
    def __init__(self, loop: asyncio.AbstractEventLoop, max_body_size: int | None):
        self.loop = loop
        self.max_body_size = max_body_size
        self.header_future: asyncio.Future = loop.create_future()
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.size = 0
        self.failed: BaseException | None = None
        self.ended = False

    def set_headers(self, status: int, headers: Headers):
        if not self.header_future.done():
            self.header_future.set_result((status, headers))

    def push(self, chunk: bytes):
        if self.failed is not None:
            return
        self.size += len(chunk)
        if self.max_body_size is not None and self.size > self.max_body_size:
            self.fail(ValueError("response body exceeds max_body_size"))
            return
        self.queue.put_nowait(chunk)

    def finish(self):
        if self.ended:
            return
        self.ended = True
        if not self.header_future.done():
            self.header_future.set_exception(ConnectionError("connection closed before response headers"))
        self.queue.put_nowait(None)

    def fail(self, exc: BaseException):
        if self.failed is not None:
            return
        self.failed = exc
        if not self.header_future.done():
            self.header_future.set_exception(exc)
        self.queue.put_nowait(None)

def dispatch_event(streams: dict[int, StreamState], event: tuple):
    kind = event[0]

    if kind == "response":
        _, stream_id, status, headers = event
        state = streams.get(stream_id)
        if state is not None:
            state.set_headers(status, headers)

    elif kind == "data":
        _, stream_id, chunk = event
        state = streams.get(stream_id)
        if state is not None:
            state.push(chunk)

    elif kind == "end":
        _, stream_id = event
        state = streams.get(stream_id)
        if state is not None:
            state.finish()

    elif kind == "reset":
        _, stream_id = event
        state = streams.get(stream_id)
        if state is not None:
            state.fail(ConnectionError("stream reset by peer"))

    elif kind == "close":
        for state in list(streams.values()):
            state.fail(ConnectionError("connection closed by peer"))

async def consume_response(state: StreamState, streaming: bool, protocol: str, read_timeout: float, on_done) -> Response:
    status, headers = await asyncio.wait_for(state.header_future, read_timeout)

    if streaming:
        async def body_iter() -> AsyncIterator[bytes]:
            try:
                while True:
                    chunk = await state.queue.get()
                    if chunk is None:
                        break
                    yield chunk
                if state.failed is not None:
                    raise state.failed
            finally:
                on_done()

        return Response(body=body_iter(), status_code=status, headers=headers, protocol=protocol)

    body = bytearray()
    while True:
        chunk = await asyncio.wait_for(state.queue.get(), read_timeout)
        if chunk is None:
            break
        body.extend(chunk)

    if state.failed is not None:
        on_done()
        raise state.failed

    on_done()
    return Response(body=bytes(body) if body else None, status_code=status, headers=headers, protocol=protocol)

def split_url(url: str) -> tuple[str, str, int, str, str]:
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "http").lower()

    scheme = {"ws": "http", "wss": "https"}.get(scheme, scheme)

    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {scheme!r}")

    host = parsed.hostname
    if not host:
        raise ValueError(f"missing host in URL: {url!r}")

    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    net_host = f"[{host}]" if ":" in host else host
    authority = net_host if port == default_port else f"{net_host}:{port}"

    return scheme, host, port, target, authority

def build_request(method: str, url: str, config: Config, headers: dict[str, str] | None, body: bytes | None) -> tuple[Request, str, int, str]:
    scheme, host, port, target, authority = split_url(url)

    h = Headers(headers or {})
    h.set("Host", authority, override=False)
    h.set("User-Agent", config.user_agent, override=False)
    h.set("Accept", "*/*", override=False)

    if config.decompress:
        h.set("Accept-Encoding", "zstd, br, gzip, deflate", override=False)

    request = Request(method=method.upper(), target=target, scheme=scheme, secure=scheme == "https", headers=h, body=body)

    return request, host, port, authority

class TCPClientProtocol(asyncio.Protocol):
    def __init__(self, handler: Handler, key: tuple, authority: str):
        self.handler = handler
        self.key = key
        self.authority = authority

        self.transport: asyncio.Transport | None = None
        self.ready: asyncio.Future = asyncio.get_running_loop().create_future()
        self.closed = False

        self.mode: Literal["h1", "h2"] = "h1"
        self.multiplexed = False

        # HTTP/1.1
        self.buffer = bytearray()
        self.current: StreamState | None = None
        self.method = "GET"
        self.state = "idle"
        self.remaining = 0
        self.chunk_remaining = 0
        self.headers: Headers | None = None
        self.reusable = False

        # HTTP/2
        self.h2: H2 | None = None
        self.h2_settings: asyncio.Event = asyncio.Event()
        self.streams: dict[int, StreamState] = {}

    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport = transport

        ssl_object: ssl.SSLObject | None = transport.get_extra_info("ssl_object")
        if ssl_object is not None and ssl_object.selected_alpn_protocol() == "h2":
            self.mode = "h2"
            self.multiplexed = True
            self.h2 = H2(client_side=True, max_body_size=self.handler.config.max_body_size, max_concurrent_streams=self.handler.config.max_concurrent_streams)
            self.transport.write(self.h2.initiate())

        if not self.ready.done():
            self.ready.set_result(None)

    def data_received(self, data: bytes):
        if self.mode == "h2":
            self.feed_h2(data)
        else:
            self.feed_h1(data)

    def connection_lost(self, exc: BaseException | None):
        self.closed = True
        self.transport = None

        if self.h2 is not None:
            for queue in self.h2.websocket_streams.values():
                queue.put_nowait(None)
            for state in list(self.streams.values()):
                state.fail(exc or ConnectionError("connection closed"))

        if self.current is not None:
            if self.state == "close":
                self.current.finish()
            elif not self.current.ended:
                self.current.fail(exc or ConnectionError("connection closed"))
            self.current = None

    def is_open(self) -> bool:
        return self.transport is not None and not self.closed

    def keepalive(self) -> bool:
        if self.headers is None:
            return False
        return "close" not in (self.headers.get("Connection") or "").lower()

    def close(self):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    async def request(self, request: Request, streaming: bool) -> Response:
        if self.mode == "h2":
            return await self.h2_request(request, streaming)
        return await self.h1_request(request, streaming)

    def feed_h1(self, data: bytes):
        self.buffer.extend(data)

        while self.current is not None:
            if self.state == "head":
                idx = self.buffer.find(b"\r\n\r\n")
                if idx == -1:
                    if len(self.buffer) > MAX_RESPONSE_HEADER_SIZE:
                        self.fail_h1(ValueError("response header too large"))
                    return

                head = bytes(self.buffer[:idx])
                del self.buffer[:idx + 4]

                try:
                    status, _, headers = H1.parse_response_head(head)
                except ValueError as exc:
                    self.fail_h1(exc)
                    return

                if 100 <= status < 200 and status != 101:
                    continue

                self.headers = headers

                if H1.response_has_no_body(status, self.method):
                    self.current.set_headers(status, headers)
                    self.finish_h1()
                    return

                transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
                content_length = headers.get("Content-Length")

                if transfer_encoding:
                    te_tokens = [t.strip() for t in transfer_encoding.split(",") if t.strip()]

                    if te_tokens[-1:] != ["chunked"]:
                        self.fail_h1(ValueError("invalid Transfer-Encoding"))
                        return

                    self.current.set_headers(status, headers)
                    self.state = "chunk-size"

                elif content_length is not None:
                    if isinstance(content_length, list) or not (content_length.isascii() and content_length.isdigit()):
                        self.fail_h1(ValueError("invalid Content-Length"))
                        return

                    self.remaining = int(content_length)
                    self.current.set_headers(status, headers)

                    if self.remaining == 0:
                        self.finish_h1()
                        return

                    self.state = "length"

                else:
                    self.current.set_headers(status, headers)
                    self.state = "close"

            elif self.state == "length":
                if not self.buffer:
                    return

                take = min(self.remaining, len(self.buffer))
                self.current.push(bytes(self.buffer[:take]))

                del self.buffer[:take]
                self.remaining -= take

                if self.remaining == 0:
                    self.finish_h1()
                    return

                return

            elif self.state == "close":
                if self.buffer:
                    self.current.push(bytes(self.buffer))
                    self.buffer.clear()

                return

            elif self.state in ("chunk-size", "chunk-data", "chunk-data-crlf", "chunk-trailer"):
                if not self.feed_h1_chunked():
                    return

            else:
                return

    def feed_h1_chunked(self) -> bool:
        if self.state == "chunk-size":
            end = self.buffer.find(b"\r\n")
            if end == -1:
                return False

            line = bytes(self.buffer[:end]).split(b";", 1)[0].strip()
            del self.buffer[:end + 2]

            try:
                size = int(line, 16)

            except ValueError:
                self.fail_h1(ValueError("invalid chunk size"))
                return False

            if size < 0:
                self.fail_h1(ValueError("negative chunk size"))
                return False

            if size == 0:
                self.state = "chunk-trailer"
                return True

            self.chunk_remaining = size
            self.state = "chunk-data"
            return True

        if self.state == "chunk-data":
            if not self.buffer:
                return False

            take = min(self.chunk_remaining, len(self.buffer))
            self.current.push(bytes(self.buffer[:take]))

            del self.buffer[:take]
            self.chunk_remaining -= take

            if self.chunk_remaining == 0:
                self.state = "chunk-data-crlf"

            return True

        if self.state == "chunk-data-crlf":
            if len(self.buffer) < 2:
                return False

            if bytes(self.buffer[:2]) != b"\r\n":
                self.fail_h1(ValueError("malformed chunk terminator"))
                return False

            del self.buffer[:2]

            self.state = "chunk-size"
            return True

        if self.state == "chunk-trailer":
            end = self.buffer.find(b"\r\n")
            if end == -1:
                return False

            is_empty = end == 0

            del self.buffer[:end + 2]

            if is_empty:
                self.finish_h1()
                return False

            return True

        return False

    async def h1_request(self, request: Request, streaming: bool) -> Response:
        if self.transport is None:
            raise ConnectionError("connection is not available")

        self.method = request.method
        self.reusable = False
        self.current = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size)
        self.headers = None
        self.state = "head"

        if request.body:
            request.headers.set("Content-Length", str(len(request.body)), override=True)

        elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
            request.headers.set("Content-Length", "0", override=False)

        request.headers.set("Connection", "keep-alive", override=False)

        self.transport.write(H1.build_request(request))

        def on_done():
            self.handler.release_h1(self)

        try:
            return await consume_response(self.current, streaming, "HTTP/1.1", self.handler.config.read_timeout, on_done)
        except BaseException:
            self.close()
            self.handler.discard(self)
            raise

    def finish_h1(self):
        if self.current is not None:
            self.current.finish()
        self.reusable = self.is_open() and self._keepalive()
        self.current = None
        self.state = "idle"

    def fail_h1(self, exc: BaseException):
        if self.current is not None:
            self.current.fail(exc)
            self.current = None
        self.reusable = False
        self.state = "idle"
        self.close()

    def feed_h2(self, data: bytes):
        if self.h2 is None or self.transport is None:
            return

        out, events, closed = self.h2.receive_response(data)
        if out:
            self.transport.write(out)

        for event in events:
            if event[0] == "settings":
                self.h2_settings.set()
                continue
            dispatch_event(self.streams, event)

        if closed:
            self.close()

    async def h2_request(self, request: Request, streaming: bool) -> Response:
        if self.h2 is None or self.transport is None:
            raise ConnectionError("connection is not available")

        stream_id, out = self.h2.send_request(request, self.authority)
        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size)
        self.streams[stream_id] = state

        if out:
            self.transport.write(out)

        def on_done():
            self.streams.pop(stream_id, None)

        try:
            return await consume_response(state, streaming, "HTTP/2.0", self.handler.config.read_timeout, on_done)
        except BaseException:
            self.streams.pop(stream_id, None)
            raise

    async def h2_websocket_read(self, stream_id: int, ws: WebSocket):
        if self.h2 is None:
            return
        queue = self.h2.websocket_streams.get(stream_id)
        if queue is None:
            return

        buf = bytearray()
        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.queue.put_nowait(None)
                break

            buf.extend(chunk)

            try:
                frames = parse_frames(buf, self.handler.config.max_websocket_message_size)
            except ValueError:
                ws.close_transport(1009)
                break

            for frame in frames:
                ws.feed_frame(frame)

    async def websocket(self, request: Request, subprotocols: list[str] | None) -> WebSocket:
        if self.h2 is None or self.transport is None:
            raise ConnectionError("connection is not available")

        await asyncio.wait_for(self.h2_settings.wait(), self.handler.config.read_timeout)

        stream_id, out = self.h2.send_connect_websocket(request, self.authority, subprotocols)
        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size)
        self.streams[stream_id] = state

        if out:
            self.transport.write(out)

        try:
            status, headers = await asyncio.wait_for(state.header_future, self.handler.config.read_timeout)
        finally:
            self.streams.pop(stream_id, None)

        if status != 200:
            self.h2.discard_send(stream_id)
            raise ConnectionError(f"websocket upgrade rejected with status {status}")

        subprotocol = (headers.get("Sec-WebSocket-Protocol") or "").strip() or None
        ws = WebSocket(H2ClientWSTransport(self, stream_id), require_masking=False, mask_frames=True, subprotocol=subprotocol, max_message_size=self.handler.config.max_websocket_message_size)

        self.handler.create_task(self._h2_websocket_read(stream_id, ws))
        return ws

class H2ClientWSTransport:
    def __init__(self, conn: TCPClientProtocol, stream_id: int):
        self.conn = conn
        self.stream_id = stream_id

    def write(self, data: bytes):
        if self.conn.h2 is None or self.conn.transport is None:
            return
        out = self.conn.h2.send_body_chunk(self.stream_id, data, end_stream=False)
        if out:
            self.conn.transport.write(out)

    def close(self):
        if self.conn.h2 is None or self.conn.transport is None:
            return
        out = self.conn.h2.websocket_close(self.stream_id)
        if out:
            self.conn.transport.write(out)

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, handler: Handler | None = None, authority: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler
        self.authority = authority
        self.h3: H3 | None = None
        self.streams: dict[int, StreamState] = {}
        self.multiplexed = True
        self.closed = False
        self.cm = None

    def quic_event_received(self, event):
        if self.h3 is None:
            self.h3 = H3(self._quic, max_body_size=self.handler.config.max_body_size if self.handler else 16 * 1024 * 1024)

        for kaede_event in self.h3.handle_event_client(event):
            dispatch_event(self.streams, kaede_event)

    def connection_lost(self, exc: BaseException | None):
        self.closed = True
        if self.h3 is not None:
            for queue in self.h3.websocket_streams.values():
                queue.put_nowait(None)
        for state in list(self.streams.values()):
            state.fail(exc or ConnectionError("connection closed"))
        super().connection_lost(exc)

    def is_open(self) -> bool:
        return not self.closed

    async def request(self, request: Request, streaming: bool) -> Response:
        if self.h3 is None:
            self.h3 = H3(self._quic, max_body_size=self.handler.config.max_body_size if self.handler else 16 * 1024 * 1024)

        stream_id = self.h3.send_request(request, self.authority)
        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size if self.handler else None)
        self.streams[stream_id] = state
        self.transmit()

        read_timeout = self.handler.config.read_timeout if self.handler else 60

        def on_done():
            self.streams.pop(stream_id, None)

        try:
            return await consume_response(state, streaming, "HTTP/3.0", read_timeout, on_done)
        except BaseException:
            self.streams.pop(stream_id, None)
            raise

    async def websocket(self, request: Request, subprotocols: list[str] | None) -> WebSocket:
        if self.h3 is None:
            self.h3 = H3(self._quic, max_body_size=self.handler.config.max_body_size if self.handler else 16 * 1024 * 1024)

        stream_id = self.h3.send_connect_websocket(request, self.authority, subprotocols)
        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size if self.handler else None)
        self.streams[stream_id] = state
        self.transmit()

        read_timeout = self.handler.config.read_timeout if self.handler else 60
        try:
            status, headers = await asyncio.wait_for(state.header_future, read_timeout)
        finally:
            self.streams.pop(stream_id, None)

        if status != 200:
            raise ConnectionError(f"websocket upgrade rejected with status {status}")

        subprotocol = (headers.get("Sec-WebSocket-Protocol") or "").strip() or None
        max_size = self.handler.config.max_websocket_message_size if self.handler else 4 * 1024 * 1024
        ws = WebSocket(H3ClientWSTransport(self, stream_id), require_masking=False, mask_frames=True, subprotocol=subprotocol, max_message_size=max_size)

        if self.handler is not None:
            self.handler.create_task(self.h3_websocket_read(stream_id, ws))
        return ws

    async def h3_websocket_read(self, stream_id: int, ws: WebSocket):
        if self.h3 is None:
            return
        queue = self.h3.websocket_streams.get(stream_id)
        if queue is None:
            return

        max_size = self.handler.config.max_websocket_message_size if self.handler else 4 * 1024 * 1024
        buf = bytearray()
        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.queue.put_nowait(None)
                break
            buf.extend(chunk)
            try:
                frames = parse_frames(buf, max_size)
            except ValueError:
                ws.close_transport(1009)
                break
            for frame in frames:
                ws.feed_frame(frame)

    async def aclose(self):
        self.close()
        if self.cm is not None:
            try:
                await self.cm.__aexit__(None, None, None)
            except Exception:
                pass

class H3ClientWSTransport:
    def __init__(self, conn: H3ClientProtocol, stream_id: int):
        self.conn = conn
        self.stream_id = stream_id

    def write(self, data: bytes):
        if self.conn.h3 is None:
            return
        self.conn.h3.send_body_chunk(self.stream_id, data, end_stream=False)
        self.conn.transmit()

    def close(self):
        if self.conn.h3 is None:
            return
        self.conn.h3.websocket_close(self.stream_id)
        self.conn.transmit()

class WSClientProtocol(asyncio.Protocol):
    def __init__(self, loop: asyncio.AbstractEventLoop, max_message_size: int):
        self.transport: asyncio.Transport | None = None
        self.buffer = bytearray()
        self.handshake: asyncio.Future = loop.create_future()
        self.ws: WebSocket | None = None
        self.max_message_size = max_message_size

    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport = transport

    def data_received(self, data: bytes):
        if self.ws is None:
            self.buffer.extend(data)
            idx = self.buffer.find(b"\r\n\r\n")
            if idx == -1:
                if len(self.buffer) > MAX_RESPONSE_HEADER_SIZE and not self.handshake.done():
                    self.handshake.set_exception(ValueError("websocket handshake header too large"))
                return
            head = bytes(self.buffer[:idx])
            del self.buffer[:idx + 4]
            if not self.handshake.done():
                self.handshake.set_result(head)
            return

        self.buffer.extend(data)
        try:
            frames = parse_frames(self.buffer, self.max_message_size)
        except ValueError:
            self.ws.close_transport(1009)
            return
        for frame in frames:
            self.ws.feed_frame(frame)

    def activate(self, ws: WebSocket):
        self.ws = ws
        if self.buffer:
            try:
                frames = parse_frames(self.buffer, self.max_message_size)
            except ValueError:
                ws.close_transport(1009)
                return
            for frame in frames:
                ws.feed_frame(frame)

    def connection_lost(self, exc: BaseException | None):
        if not self.handshake.done():
            self.handshake.set_exception(exc or ConnectionError("connection closed during websocket handshake"))
        if self.ws is not None and not self.ws.closed:
            self.ws.queue.put_nowait(None)

class Handler:
    def __init__(self, config: Config):
        self.config = config

        self.shared: dict[tuple, object] = {}
        self.idle: dict[tuple, list[TCPClientProtocol]] = {}
        self.locks: dict[tuple, asyncio.Lock] = {}
        self.origin_kind: dict[tuple, str] = {}
        self.connections: set = set()
        self.tasks: set[asyncio.Task] = set()

        self._ssl_context: ssl.SSLContext | None = None

    def create_task(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def ssl_context(self) -> ssl.SSLContext:
        if self._ssl_context is None:
            self._ssl_context = TLS.from_client_config(self.config).context
        return self._ssl_context

    def ordered_kinds(self) -> list[str]:
        protocols = self.config.protocols
        kinds: list[tuple[str, int]] = []

        if "h3" in protocols:
            kinds.append(("h3", protocols.index("h3")))

        tls = [p for p in ("h2", "http/1.1") if p in protocols]
        if tls:
            kinds.append(("tls", min(protocols.index(p) for p in tls)))

        kinds.sort(key=lambda item: item[1])
        return [kind for kind, _ in kinds]

    async def get_connection(self, scheme: str, host: str, port: int, authority: str):
        key = (scheme, host, port)

        shared = self.shared.get(key)
        if shared is not None and shared.is_open():
            return shared

        lock = self.locks.setdefault(key, asyncio.Lock())
        async with lock:
            shared = self.shared.get(key)
            if shared is not None and shared.is_open():
                return shared

            idle = self.idle.get(key)
            while idle:
                conn = idle.pop()
                if conn.is_open():
                    return conn

            conn = await self.establish(scheme, host, port, authority)
            self.connections.add(conn)
            if getattr(conn, "multiplexed", False):
                self.shared[key] = conn
            return conn

    async def establish(self, scheme: str, host: str, port: int, authority: str):
        key = (scheme, host, port)

        if scheme == "http":
            return await self.connect_tcp(key, host, port, authority, None)

        kinds = self.ordered_kinds()
        cached = self.origin_kind.get(key)
        if cached:
            kinds = [cached] + [k for k in kinds if k != cached]

        last_error: BaseException | None = None
        for kind in kinds:
            try:
                if kind == "h3":
                    conn = await self.connect_quic(host, port, authority)
                else:
                    conn = await self.connect_tcp(key, host, port, authority, self.ssl_context())
                self.origin_kind[key] = kind
                return conn
            except Exception as exc:
                last_error = exc

        raise last_error or ConnectionError(f"failed to connect to {host}:{port}")

    async def connect_tcp(self, key: tuple, host: str, port: int, authority: str, ssl_context: ssl.SSLContext | None) -> TCPClientProtocol:
        loop = asyncio.get_running_loop()
        protocol = TCPClientProtocol(self, key, authority)

        await asyncio.wait_for(loop.create_connection(lambda: protocol, host, port, ssl=ssl_context, server_hostname=host if ssl_context else None), timeout=self.config.connect_timeout)
        await protocol.ready
        return protocol

    async def connect_quic(self, host: str, port: int, authority: str) -> H3ClientProtocol:
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], max_datagram_frame_size=65536)
        configuration.server_name = host

        if self.config.tls.verify:
            if self.config.tls.cafile or self.config.tls.capath:
                configuration.load_verify_locations(cafile=self.config.tls.cafile, capath=self.config.tls.capath)
        else:
            configuration.verify_mode = ssl.CERT_NONE

        cm = quic_connect(host, port, configuration=configuration, create_protocol=lambda *a, **kw: H3ClientProtocol(*a, handler=self, authority=authority, **kw), wait_connected=True)

        try:
            protocol = await asyncio.wait_for(cm.__aenter__(), timeout=self.config.connect_timeout)
        except BaseException:
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                pass
            raise

        protocol.cm = cm
        return protocol

    def release_h1(self, conn: TCPClientProtocol):
        if conn.is_open() and conn.reusable:
            self.idle.setdefault(conn.key, []).append(conn)
        else:
            self.discard(conn)
            conn.close()

    def discard(self, conn):
        self.connections.discard(conn)
        key = getattr(conn, "key", None)
        if key is not None and self.shared.get(key) is conn:
            self.shared.pop(key, None)
        idle = self.idle.get(getattr(conn, "key", None))
        if idle and conn in idle:
            idle.remove(conn)

    async def request(self, method: str, url: str, headers: dict[str, str] | None, body: bytes | None, streaming: bool) -> Response:
        request, host, port, authority = build_request(method, url, self.config, headers, body)
        conn = await self.get_connection(request.scheme, host, port, authority)

        response = await conn.request(request, streaming)

        if streaming:
            response = wrap_streaming_response(response, self.config)
        else:
            response = await process_response(response, request, self.config)

        return response

    async def websocket(self, url: str, subprotocols: list[str] | None, headers: dict[str, str] | None) -> WebSocket:
        scheme, host, port, target, authority = split_url(url)

        h = Headers(headers or {})
        h.set("Host", authority, override=False)
        h.set("User-Agent", self.config.user_agent, override=False)
        request = Request(method="GET", target=target, scheme=scheme, secure=scheme == "https", headers=h)

        key = (scheme, host, port)

        if scheme == "http":
            return await self.websocket_h1(host, port, authority, request, subprotocols, None)

        last_error: BaseException | None = None
        for kind in self.ordered_kinds():
            try:
                if kind == "h3":
                    conn = await self.connect_quic(host, port, authority)
                    self.connections.add(conn)
                    return await conn.websocket(request, subprotocols)

                conn = await self.connect_tcp(key, host, port, authority, self.ssl_context())
                self.connections.add(conn)

                if conn.mode == "h2":
                    return await conn.websocket(request, subprotocols)

                conn.close()
                self.discard(conn)
                return await self.websocket_h1(host, port, authority, request, subprotocols, self.ssl_context())

            except Exception as exc:
                last_error = exc

        raise last_error or ConnectionError(f"failed to establish websocket to {host}:{port}")

    async def websocket_h1(self, host: str, port: int, authority: str, request: Request, subprotocols: list[str] | None, ssl_context: ssl.SSLContext | None) -> WebSocket:
        loop = asyncio.get_running_loop()
        protocol = WSClientProtocol(loop, self.config.max_websocket_message_size)

        await asyncio.wait_for(
            loop.create_connection(lambda: protocol, host, port, ssl=ssl_context, server_hostname=host if ssl_context else None),
            timeout=self.config.connect_timeout,
        )

        key = generate_key()
        request.headers.set("Upgrade", "websocket")
        request.headers.set("Connection", "Upgrade")
        request.headers.set("Sec-WebSocket-Key", key)
        request.headers.set("Sec-WebSocket-Version", "13")
        if subprotocols:
            request.headers.set("Sec-WebSocket-Protocol", ", ".join(subprotocols))

        if protocol.transport is not None:
            protocol.transport.write(H1.build_request(request))

        head = await asyncio.wait_for(protocol.handshake, self.config.read_timeout)
        status, _, headers = H1.parse_response_head(head)

        accept = headers.get("Sec-WebSocket-Accept") or ""
        upgrade = (headers.get("Upgrade") or "").lower()
        if status != 101 or upgrade != "websocket" or not check_accept(key, accept if isinstance(accept, str) else ""):
            protocol.transport.close()
            raise ConnectionError(f"websocket upgrade failed (status {status})")

        subprotocol = (headers.get("Sec-WebSocket-Protocol") or "").strip() or None
        ws = WebSocket(protocol.transport, require_masking=False, mask_frames=True, subprotocol=subprotocol, max_message_size=self.config.max_websocket_message_size)
        protocol.activate(ws)
        return ws

    async def close(self):
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

        for conn in list(self.connections):
            if isinstance(conn, H3ClientProtocol):
                await conn.aclose()
            else:
                conn.close()

        for connections in self.idle.values():
            for conn in connections:
                conn.close()

        self.connections.clear()
        self.shared.clear()
        self.idle.clear()

class StreamContext:
    def __init__(self, handler: Handler, method: str, url: str, headers: dict[str, str] | None, body: bytes | None):
        self.handler = handler
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.response: Response | None = None

    async def __aenter__(self) -> Response:
        self.response = await self.handler.request(self.method, self.url, self.headers, self.body, streaming=True)
        return self.response

    async def __aexit__(self, *exc):
        if self.response is not None and hasattr(self.response.body, "aclose"):
            try:
                await self.response.body.aclose()
            except Exception:
                pass

class Client:
    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.handler = Handler(self.config)

    async def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        return await self.handler.request(method, url, headers, body, streaming=False)

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> Response:
        return await self.request("GET", url, headers=headers)

    async def head(self, url: str, *, headers: dict[str, str] | None = None) -> Response:
        return await self.request("HEAD", url, headers=headers)

    async def post(self, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        return await self.request("POST", url, headers=headers, body=body)

    async def put(self, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        return await self.request("PUT", url, headers=headers, body=body)

    async def patch(self, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        return await self.request("PATCH", url, headers=headers, body=body)

    async def delete(self, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        return await self.request("DELETE", url, headers=headers, body=body)

    async def options(self, url: str, *, headers: dict[str, str] | None = None) -> Response:
        return await self.request("OPTIONS", url, headers=headers)

    def stream(self, method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> StreamContext:
        return StreamContext(self.handler, method, url, headers, body)

    async def websocket(self, url: str, *, subprotocols: list[str] | None = None, headers: dict[str, str] | None = None) -> WebSocket:
        return await self.handler.websocket(url, subprotocols, headers)

    async def close(self):
        await self.handler.close()

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *exc):
        await self.close()
