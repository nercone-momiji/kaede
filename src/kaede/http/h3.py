from __future__ import annotations

import os
import asyncio
import ipaddress
from dataclasses import dataclass

from . import qpack
from ..models import Request, Response, Headers
from ..process import process_request
from ..quic import QUICConnection, HandshakeCompleted, StreamDataReceived, ConnectionTerminated
from ..quic.packet import Buffer, encode_uint_var
from ..quic.stream import stream_is_bidirectional
from ..tls.quic_tls import QuicTLS
from ..handler.common import StreamState, consume_response

H3_FORBIDDEN_HEADERS = ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection")

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_CANCEL_PUSH = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_GOAWAY = 0x7
FRAME_MAX_PUSH_ID = 0xD

STREAM_CONTROL = 0x00
STREAM_PUSH = 0x01
STREAM_QPACK_ENCODER = 0x02
STREAM_QPACK_DECODER = 0x03

SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06
SETTINGS_QPACK_BLOCKED_STREAMS = 0x07
SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08

@dataclass
class H3Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H3WSUpgrade:
    stream_id: int
    request: object

@dataclass
class HeadersReceived:
    stream_id: int
    headers: list[tuple[bytes, bytes]]
    stream_ended: bool = False

@dataclass
class DataReceived:
    stream_id: int
    data: bytes
    stream_ended: bool = False

def peername(addr) -> tuple:
    try:
        return (ipaddress.ip_address(addr[0]), int(addr[1]))
    except (ValueError, IndexError, TypeError):
        return (ipaddress.IPv4Address("0.0.0.0"), 0)

class H3:
    """Stateless HTTP/3 protocol helpers (framing, settings, headers).

    Per-connection state (QUIC stream management, request/response assembly)
    is owned by :class:`H3Connection`.
    """

    @staticmethod
    def encode_frame(frame_type: int, payload: bytes) -> bytes:
        return encode_uint_var(frame_type) + encode_uint_var(len(payload)) + payload

    @staticmethod
    def encode_settings() -> bytes:
        body = bytearray()

        for ident, value in ((SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0), (SETTINGS_QPACK_BLOCKED_STREAMS, 0), (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)):
            body += encode_uint_var(ident)
            body += encode_uint_var(value)

        return H3.encode_frame(FRAME_SETTINGS, bytes(body))

    @staticmethod
    def build_response_headers(response: Response) -> list[tuple[bytes, bytes]]:
        headers: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode("ascii"))]
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in H3_FORBIDDEN_HEADERS:
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))
        return headers

    @staticmethod
    def build_request_headers(request: Request, authority: str) -> list[tuple[bytes, bytes]]:
        headers: list[tuple[bytes, bytes]] = [
            (b":method", request.method.encode("ascii")),
            (b":scheme", request.scheme.encode("ascii")),
            (b":authority", authority.encode("ascii")),
            (b":path", request.target.encode("latin-1")),
        ]
        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H3_FORBIDDEN_HEADERS or lname in ("host", "content-length"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))
        return headers

class RequestAssembler:
    def __init__(self):
        self.headers: list[tuple[bytes, bytes]] | None = None
        self.body = bytearray()
        self.too_large = False

class H3Connection:
    """Manages a single HTTP/3 connection over QUIC (server or client side).

    Wraps a :class:`~kaede.quic.QUICConnection`, manages the HTTP/3 control and
    QPACK streams, assembles requests/responses and pumps QUIC datagrams to the
    transport owned by an :class:`H3Protocol`. Stateless helpers live in
    :class:`H3`.
    """

    def __init__(self, quic: QUICConnection, protocol, is_client: bool = False, *, addr=None, authority: str = ""):
        self.quic = quic
        self.protocol = protocol
        self.handler = protocol.handler
        self.is_client = is_client
        self.addr = addr
        self.authority = authority

        self.max_body_size = self.handler.config.max_body_size if self.handler else 16 * 1024 * 1024

        # H3 framing state
        self.control_stream_id: int | None = None
        self.peer_uni_types: dict[int, int] = {}
        self.uni_buffers: dict[int, bytearray] = {}
        self.request_buffers: dict[int, bytearray] = {}
        self.finished: set[int] = set()

        # server state
        self.client = peername(addr) if addr is not None else (ipaddress.IPv4Address("0.0.0.0"), 0)
        self.tls = None
        self.assemblers: dict[int, RequestAssembler] = {}

        # client state
        self.streams: dict[int, StreamState] = {}
        self.headers_seen: dict[int, bool] = {}
        self.multiplexed = True
        self.mode = "h3"
        self.closed = False
        self.connected: asyncio.Future = asyncio.get_running_loop().create_future()

        self.timer: asyncio.TimerHandle | None = None

        self.setup()

    @property
    def config(self):
        return self.handler.config

    def now(self) -> float:
        return asyncio.get_running_loop().time()

    # --- H3 framing ---

    def setup(self):
        self.control_stream_id = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(self.control_stream_id, encode_uint_var(STREAM_CONTROL) + H3.encode_settings(), end_stream=False)

        enc = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(enc, encode_uint_var(STREAM_QPACK_ENCODER), end_stream=False)

        dec = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(dec, encode_uint_var(STREAM_QPACK_DECODER), end_stream=False)

    def open_request_stream(self) -> int:
        return self.quic.get_next_available_stream_id(is_bidi=True)

    def send_headers(self, stream_id: int, headers: list[tuple[bytes, bytes]], end_stream: bool = False):
        field_section = qpack.encode_headers(headers)
        self.quic.send_stream_data(stream_id, H3.encode_frame(FRAME_HEADERS, field_section), end_stream=end_stream)

    def send_data(self, stream_id: int, data: bytes, end_stream: bool = False):
        self.quic.send_stream_data(stream_id, H3.encode_frame(FRAME_DATA, data), end_stream=end_stream)

    def feed(self, events: list) -> list:
        out: list = []

        for event in events:
            if not isinstance(event, StreamDataReceived):
                continue

            sid = event.stream_id

            if stream_is_bidirectional(sid):
                self.feed_request_stream(sid, event.data, event.end_stream, out)

            else:
                self.feed_uni_stream(sid, event.data, event.end_stream)

        return out

    def feed_uni_stream(self, sid: int, data: bytes, end_stream: bool):
        buf = self.uni_buffers.setdefault(sid, bytearray())
        buf.extend(data)

        if sid not in self.peer_uni_types:
            reader = Buffer(bytes(buf))

            try:
                stream_type = reader.pull_uint_var()
            except Exception:
                return

            self.peer_uni_types[sid] = stream_type

            del buf[:reader.tell()]

        buf.clear()

    def feed_request_stream(self, sid: int, data: bytes, end_stream: bool, out: list):
        buf = self.request_buffers.setdefault(sid, bytearray())
        buf.extend(data)

        while True:
            reader = Buffer(bytes(buf))

            try:
                frame_type = reader.pull_uint_var()
                length = reader.pull_uint_var()
            except Exception:
                break

            header_len = reader.tell()

            if len(buf) - header_len < length:
                break

            payload = bytes(buf[header_len:header_len + length])

            del buf[:header_len + length]

            if frame_type == FRAME_HEADERS:
                try:
                    headers = qpack.decode_headers(payload)
                except qpack.QpackError:
                    return
                out.append(HeadersReceived(sid, headers, stream_ended=False))
            elif frame_type == FRAME_DATA:
                out.append(DataReceived(sid, payload, stream_ended=False))

        if end_stream and sid not in self.finished:
            self.finished.add(sid)
            out.append(DataReceived(sid, b"", stream_ended=True))

    # --- datagram processing ---

    def receive_datagram(self, data: bytes) -> bool:
        self.quic.receive_datagram(data, self.now())
        events = self.quic.events()
        terminated = False

        for event in events:
            if isinstance(event, HandshakeCompleted):
                if self.is_client:
                    if not self.connected.done():
                        self.connected.set_result(None)
                elif self.tls is None:
                    self.tls = self.quic.tls.info()

            elif isinstance(event, ConnectionTerminated):
                terminated = True
                if self.is_client:
                    self.fail_all(ConnectionError("connection terminated"))

        for h3ev in self.feed(events):
            if self.is_client:
                self.on_client_event(h3ev)
            else:
                self.on_server_event(h3ev)

        self.flush()

        return terminated

    def flush(self):
        now = self.now()
        for data, _ in self.quic.datagrams_to_send(now):
            if self.protocol.transport is not None:
                self.protocol.transport.sendto(data, self.addr)
        self.schedule_timer()

    def schedule_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        when = self.quic.get_timer()

        if when is not None:
            loop = asyncio.get_running_loop()
            self.timer = loop.call_at(loop.time() + max(0.0, when - self.now()), self.on_timer)

    def on_timer(self):
        self.timer = None
        self.quic.handle_timer(self.now())
        self.flush()

    # --- server: request assembly + response ---

    def on_server_event(self, ev):
        if isinstance(ev, HeadersReceived):
            asm = self.assemblers.setdefault(ev.stream_id, RequestAssembler())
            asm.headers = ev.headers

        elif isinstance(ev, DataReceived):
            asm = self.assemblers.get(ev.stream_id)

            if asm is None:
                return

            if ev.data:
                asm.body.extend(ev.data)

                if len(asm.body) > self.max_body_size:
                    asm.too_large = True

            if ev.stream_ended:
                self.dispatch(ev.stream_id, asm)

    def dispatch(self, stream_id: int, asm: RequestAssembler):
        self.assemblers.pop(stream_id, None)
        if asm.headers is None:
            return
        if asm.too_large:
            self.send_headers(stream_id, [(b":status", b"413")], end_stream=True)
            self.flush()
            return
        request = self.build_request(stream_id, asm)
        self.handler.create_task(self.respond(request))

    def build_request(self, stream_id: int, asm: RequestAssembler) -> Request:
        method = "GET"
        target = "/"
        authority = ""
        headers = Headers({})

        for nameb, valueb in asm.headers:
            name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
            value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb

            if name == ":method":
                method = value

            elif name == ":path":
                target = value

            elif name == ":authority":
                authority = value
                headers.append("host", value)

            elif not name.startswith(":"):
                headers.append(name, value)

        body = bytes(asm.body) if asm.body else None

        return Request(client=self.client, scheme="https", secure=True, protocol="HTTP/3.0", method=method, target=target, headers=headers, body=body, h2=None, h3=H3Info(connection_id=self.quic.local_cid, stream_id=stream_id), tls=self.tls)

    async def respond(self, request: Request):
        if request.h3 is None:
            return

        stream_id = request.h3.stream_id
        response = await process_request(request, callback=self.handler.callback, config=self.config)

        if response.is_streaming:
            await self.stream(stream_id, response)
            return

        headers = H3.build_response_headers(response)

        if response.has_real_body:
            self.send_headers(stream_id, headers, end_stream=False)
            self.send_data(stream_id, response.body, end_stream=True)

        elif response.body is not None:
            self.send_headers(stream_id, headers, end_stream=False)
            await self.send_file(stream_id, response.body, response.file_range)

        else:
            self.send_headers(stream_id, headers, end_stream=True)

        self.flush()

    async def stream(self, stream_id: int, response: Response):
        self.send_headers(stream_id, H3.build_response_headers(response), end_stream=False)
        self.flush()

        try:
            async for chunk in response.body:
                if chunk:
                    self.send_data(stream_id, chunk, end_stream=False)
                    self.flush()
        finally:
            self.send_data(stream_id, b"", end_stream=True)
            self.flush()

    async def send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None):
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            self.send_data(stream_id, b"", end_stream=True)
            self.flush()
            return

        try:
            remaining = None

            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            pending = await loop.run_in_executor(None, fp.read, 65536 if remaining is None else min(65536, remaining))

            while pending:
                if remaining is not None:
                    remaining -= len(pending)

                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                self.send_data(stream_id, pending, end_stream=not nxt)
                self.flush()
                pending = nxt

        finally:
            await loop.run_in_executor(None, fp.close)

    # --- client: response assembly + request ---

    def on_client_event(self, ev):
        state = self.streams.get(ev.stream_id)

        if state is None:
            return

        if isinstance(ev, HeadersReceived):
            status = 0
            headers = Headers({})

            for nameb, valueb in ev.headers:
                name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
                value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb

                if name == ":status":
                    try:
                        status = int(value)
                    except ValueError:
                        status = 0

                elif not name.startswith(":"):
                    headers.append(name, value)

            state.set_headers(status, headers)

        elif isinstance(ev, DataReceived):
            if ev.data:
                state.push(ev.data)

            if ev.stream_ended:
                state.finish()

    def fail_all(self, exc: BaseException):
        self.closed = True
        if not self.connected.done():
            self.connected.set_exception(exc)
        for state in list(self.streams.values()):
            state.fail(exc)

    def is_open(self) -> bool:
        return not self.closed

    async def request(self, request: Request, streaming: bool) -> Response:
        read_timeout = self.config.read_timeout if self.handler else 60
        stream_id = self.open_request_stream()
        headers = H3.build_request_headers(request, self.authority)
        has_body = bool(request.body)
        self.send_headers(stream_id, headers, end_stream=not has_body)

        if has_body:
            self.send_data(stream_id, request.body, end_stream=True)

        state = StreamState(asyncio.get_running_loop(), self.max_body_size)

        self.streams[stream_id] = state
        self.flush()

        def on_done():
            self.streams.pop(stream_id, None)

        try:
            return await consume_response(state, streaming, "HTTP/3.0", read_timeout, on_done)
        except BaseException:
            self.streams.pop(stream_id, None)
            raise

    def lost(self, exc: BaseException | None):
        self.fail_all(exc or ConnectionError("connection lost"))

    def close(self):
        self.closed = True

        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        if self.protocol.transport is not None:
            self.protocol.transport.close()

    async def aclose(self):
        self.close()

class H3Protocol(asyncio.DatagramProtocol):
    """asyncio datagram protocol for HTTP/3 over QUIC.

    On the server a single instance multiplexes many :class:`H3Connection`
    objects keyed by peer address; on the client it drives a single connection.
    """

    def __init__(self, handler=None, *, is_client: bool = False, connection: H3Connection | None = None):
        self.handler = handler
        self.is_client = is_client
        self.transport: asyncio.DatagramTransport | None = None
        self.connection = connection
        self.connections: dict[tuple, H3Connection] = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if self.is_client:
            if self.connection is not None:
                self.connection.receive_datagram(data)
            return

        if self.handler.shutdown:
            return

        conn = self.connections.get(addr)
        if conn is None:
            if not data or not (data[0] & 0x80):
                return
            try:
                quic = QUICConnection.create_server(data, lambda tp: QuicTLS.for_server(self.handler.config.tls, transport_params=tp))
            except Exception:
                return
            conn = H3Connection(quic, self, is_client=False, addr=addr)
            self.connections[addr] = conn

        if conn.receive_datagram(data):
            self.connections.pop(addr, None)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        if self.is_client and self.connection is not None:
            self.connection.fail_all(exc or ConnectionError("connection lost"))

async def connect_quic(handler, host: str, port: int, authority: str, *, server_name: str, tls_config, connect_timeout: float) -> H3Connection:
    loop = asyncio.get_running_loop()
    quic = QUICConnection.create_client(lambda tp: QuicTLS.for_client(tls_config, server_name, transport_params=tp), server_name)

    protocol = H3Protocol(handler, is_client=True)
    conn = H3Connection(quic, protocol, is_client=True, authority=authority)
    protocol.connection = conn

    transport, _ = await loop.create_datagram_endpoint(lambda: protocol, remote_addr=(host, port))

    conn.flush()

    await asyncio.wait_for(conn.connected, timeout=connect_timeout)

    return conn
