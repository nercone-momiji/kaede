from __future__ import annotations

import os
import asyncio
import ipaddress
from dataclasses import dataclass

from . import qpack
from ..models import Request, Response, Headers
from ..process import process_request
from ..quic import QUICConnection, HandshakeCompleted, StreamDataReceived, ConnectionTerminated
from ..quic.tls import QuicTLS, QuicTLSServerContext
from ..quic.packet import Buffer, encode_uint_var, build_version_negotiation, parse_long_header
from ..quic.stream import stream_is_bidirectional
from ..handler.common import StreamState, consume_response, negotiate_websocket
from ..websocket import WebSocket, WebSocketProtocolError, parse_frames

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

FORBIDDEN_H2_SETTINGS = frozenset([0x02, 0x03, 0x04, 0x05])

@dataclass
class H3Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H3WSUpgrade:
    stream_id: int
    request: object

class H3WebSocketTransport:
    """Adapts a WebSocket to an HTTP/3 request stream: WebSocket frames are
    carried as the payload of HTTP/3 DATA frames (RFC 9220)."""

    def __init__(self, conn: "H3Connection", stream_id: int):
        self.conn = conn
        self.stream_id = stream_id

    def write(self, data: bytes):
        self.conn.send_data(self.stream_id, data, end_stream=False)
        self.conn.flush()

    def close(self):
        self.conn.send_data(self.stream_id, b"", end_stream=True)
        self.conn.flush()

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
    @staticmethod
    def encode_frame(frame_type: int, payload: bytes) -> bytes:
        return encode_uint_var(frame_type) + encode_uint_var(len(payload)) + payload

    @staticmethod
    def encode_settings(qpack_max_table_capacity: int = 0) -> bytes:
        body = bytearray()

        for ident, value in (
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, qpack_max_table_capacity),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            (0x21, 0),
        ):
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
            (b":path", request.target.encode("utf-8"))
        ]
        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H3_FORBIDDEN_HEADERS or lname in ("host", "content-length"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))
        return headers

    @staticmethod
    def build_websocket_connect_headers(request: Request, authority: str, subprotocols: list[str] | None = None) -> list[tuple[bytes, bytes]]:
        # Extended CONNECT for WebSocket over HTTP/3 (RFC 9220 / RFC 8441 §5).
        headers: list[tuple[bytes, bytes]] = [
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", request.scheme.encode("ascii")),
            (b":authority", authority.encode("ascii")),
            (b":path", request.target.encode("utf-8")),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append((b"sec-websocket-protocol", ", ".join(subprotocols).encode("ascii")))

        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H3_FORBIDDEN_HEADERS or lname in ("host", "content-length") or lname.startswith("sec-websocket"):
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

QPACK_MAX_TABLE_CAPACITY = 4096

class H3Connection:
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
        self._qpack_dec_stream_id: int | None = None
        self._qpack_decoder: qpack.QpackDecoder = qpack.QpackDecoder(QPACK_MAX_TABLE_CAPACITY)
        self.peer_uni_types: dict[int, int] = {}
        self.uni_buffers: dict[int, bytearray] = {}
        self.request_buffers: dict[int, bytearray] = {}
        self.finished: set[int] = set()

        # Peer control stream state (RFC 9114 §6.2.1)
        self.peer_control_stream_id: int | None = None
        self.peer_settings_received: bool = False
        self.peer_max_field_section_size: int | None = None
        self.peer_enable_connect: bool = False

        # server state
        self.client = peername(addr) if addr is not None else (ipaddress.IPv4Address("0.0.0.0"), 0)
        self.tls = None
        self.assemblers: dict[int, RequestAssembler] = {}
        self.last_processed_stream_id: int = -1
        # Extended-CONNECT WebSocket streams (RFC 9220): stream_id -> data queue.
        self.websocket_streams: dict[int, asyncio.Queue] = {}

        # client state
        self.streams: dict[int, StreamState] = {}
        self.websocket_pending: dict[int, asyncio.Future] = {}
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

    def setup(self):
        self.control_stream_id = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(
            self.control_stream_id,
            encode_uint_var(STREAM_CONTROL) + H3.encode_settings(QPACK_MAX_TABLE_CAPACITY),
            end_stream=False,
        )

        enc = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(enc, encode_uint_var(STREAM_QPACK_ENCODER), end_stream=False)

        dec = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(dec, encode_uint_var(STREAM_QPACK_DECODER), end_stream=False)
        self._qpack_dec_stream_id = dec

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

        if sid not in self.peer_uni_types:
            buf.extend(data)

            reader = Buffer(bytes(buf))

            try:
                stream_type = reader.pull_uint_var()
            except Exception:
                return

            self.peer_uni_types[sid] = stream_type
            del buf[:reader.tell()]

            if stream_type == STREAM_CONTROL:
                self.peer_control_stream_id = sid

        else:
            buf.extend(data)

        stream_type = self.peer_uni_types.get(sid)

        if stream_type == STREAM_CONTROL:
            self.parse_control_stream(sid, buf)
        elif stream_type == STREAM_QPACK_ENCODER:
            if buf:
                try:
                    self._qpack_decoder.feed_encoder_stream(bytes(buf))
                except qpack.QpackError:
                    self.quic.close(0x0200, "QPACK decompression failed")
                    return
                del buf[:]
        elif len(buf) > 65536:
            del self.uni_buffers[sid]

    def parse_control_stream(self, sid: int, buf: bytearray):
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

            if not self.peer_settings_received:
                if frame_type != FRAME_SETTINGS:
                    self.quic.close(0x010a, "H3_MISSING_SETTINGS")
                    return

                self.peer_settings_received = True
                self.apply_peer_settings(payload)

            elif frame_type == FRAME_SETTINGS:
                self.quic.close(0x0105, "H3_FRAME_UNEXPECTED")
                return

    def apply_peer_settings(self, payload: bytes):
        reader = Buffer(payload)
        seen_ids: set[int] = set()
        while not reader.eof():
            try:
                ident = reader.pull_uint_var()
                value = reader.pull_uint_var()
            except Exception:
                self.quic.close(0x0109, "H3_SETTINGS_ERROR")
                return

            if ident in seen_ids:
                self.quic.close(0x0109, "H3_SETTINGS_ERROR")
                return
            seen_ids.add(ident)

            if ident in FORBIDDEN_H2_SETTINGS:
                self.quic.close(0x0109, "H3_SETTINGS_ERROR")
                return

            if ident == SETTINGS_MAX_FIELD_SECTION_SIZE:
                self.peer_max_field_section_size = value
            elif ident == SETTINGS_ENABLE_CONNECT_PROTOCOL:
                self.peer_enable_connect = (value == 1)

        if self.is_client and self.control_stream_id is not None:
            self.quic.send_stream_data(self.control_stream_id, H3.encode_frame(FRAME_MAX_PUSH_ID, encode_uint_var(0)), end_stream=False)

    def feed_request_stream(self, sid: int, data: bytes, end_stream: bool, out: list):
        buf = self.request_buffers.setdefault(sid, bytearray())

        if len(buf) + len(data) > self.max_body_size + (self.handler.config.max_header_size if self.handler else 65536):
            asm = self.assemblers.get(sid)
            if asm is not None:
                self.send_headers(sid, [(b":status", b"413")], end_stream=True)
                self.flush()
            self.request_buffers.pop(sid, None)
            self.assemblers.pop(sid, None)
            return

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
                    headers = self._qpack_decoder.decode_field_section(payload, stream_id=sid)
                except qpack.QpackError:
                    self.quic.close(0x0200, "QPACK decompression failed")
                    return
                out.append(HeadersReceived(sid, headers, stream_ended=False))

            elif frame_type == FRAME_DATA:
                out.append(DataReceived(sid, payload, stream_ended=False))

            elif frame_type == FRAME_PUSH_PROMISE:
                if not self.is_client:
                    self.quic.close(0x0105, "H3_FRAME_UNEXPECTED")
                    return

            elif frame_type in (FRAME_CANCEL_PUSH, FRAME_SETTINGS, FRAME_GOAWAY, FRAME_MAX_PUSH_ID):
                self.quic.close(0x0105, "H3_FRAME_UNEXPECTED")
                return

        if end_stream and sid not in self.finished:
            self.finished.add(sid)
            out.append(DataReceived(sid, b"", stream_ended=True))

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
        # Send any pending QPACK decoder-stream instructions (ICI, Section Ack).
        if self._qpack_dec_stream_id is not None:
            pending = self._qpack_decoder.flush_decoder_instructions()
            if pending:
                self.quic.send_stream_data(self._qpack_dec_stream_id, pending, end_stream=False)

        now = self.now()
        for data, _ in self.quic.datagrams_to_send(now):
            if self.protocol.transport is not None:
                self.protocol.transport.sendto(data, self.addr)
        self.schedule_timer()

    def schedule_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        if self.quic.terminated:
            return

        when = self.quic.get_timer()

        if when is not None:
            loop = asyncio.get_running_loop()
            self.timer = loop.call_at(loop.time() + max(0.0, when - self.now()), self.on_timer)

    def on_timer(self):
        self.timer = None
        self.quic.handle_timer(self.now())

        # handle_timer may silently terminate the connection (idle timeout,
        # RFC 9000 §10.1); surface that and reap server-side connection state.
        terminated = any(isinstance(event, ConnectionTerminated) for event in self.quic.events())

        self.flush()

        if terminated:
            if self.is_client:
                self.fail_all(ConnectionError("connection terminated"))
            elif self.addr is not None:
                self.protocol._reap(self.addr)

    def on_server_event(self, ev):
        if isinstance(ev, HeadersReceived):
            # RFC 9220 / RFC 8441: an extended CONNECT request (":protocol" =
            # "websocket") bootstraps a WebSocket on this stream rather than a
            # normal request; the stream stays open for bidirectional data.
            if ev.stream_id not in self.websocket_streams and self._is_websocket_connect(ev.headers):
                request = self._build_websocket_request(ev.stream_id, ev.headers)
                if request is None:
                    self.send_headers(ev.stream_id, [(b":status", b"400")], end_stream=True)
                    self.flush()
                    return
                self.websocket_streams[ev.stream_id] = asyncio.Queue()
                self.handler.create_task(self.websocket_respond(ev.stream_id, request))
                return

            asm = self.assemblers.setdefault(ev.stream_id, RequestAssembler())
            asm.headers = ev.headers

        elif isinstance(ev, DataReceived):
            if ev.stream_id in self.websocket_streams:
                if ev.data:
                    self.websocket_streams[ev.stream_id].put_nowait(ev.data)
                if ev.stream_ended:
                    self.websocket_streams[ev.stream_id].put_nowait(None)
                return

            asm = self.assemblers.get(ev.stream_id)

            if asm is None:
                if ev.data:
                    self.quic.close(0x0105, "H3_FRAME_UNEXPECTED: DATA before HEADERS")
                return

            if ev.data and not asm.too_large:
                if len(asm.body) + len(ev.data) > self.max_body_size:
                    asm.too_large = True
                else:
                    asm.body.extend(ev.data)

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

        for nameb, valueb in asm.headers:
            name = nameb.decode("ascii", "replace").lower() if isinstance(nameb, (bytes, bytearray)) else nameb.lower()
            if name.startswith(":"):
                continue
            if name in H3_FORBIDDEN_HEADERS:
                self.send_headers(stream_id, [(b":status", b"400")], end_stream=True)
                self.flush()
                return
            if name == "te":
                val = valueb.decode("utf-8", "replace").strip().lower() if isinstance(valueb, (bytes, bytearray)) else valueb.strip().lower()
                if val != "trailers":
                    self.send_headers(stream_id, [(b":status", b"400")], end_stream=True)
                    self.flush()
                    return

        request = self.build_request(stream_id, asm)

        if request is None:
            self.send_headers(stream_id, [(b":status", b"400")], end_stream=True)
            self.flush()
            return

        self.last_processed_stream_id = max(self.last_processed_stream_id, stream_id)
        self.handler.create_task(self.respond(request))

    def build_request(self, stream_id: int, asm: RequestAssembler) -> Request | None:
        method: str | None = None
        target: str | None = None
        authority = ""
        scheme: str | None = None
        has_scheme = False
        has_path = False
        headers = Headers({})

        for nameb, valueb in asm.headers:
            name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
            value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb

            if name == ":method":
                method = value

            elif name == ":scheme":
                scheme = value if value in ("http", "https") else "https"
                has_scheme = True

            elif name == ":path":
                target = value
                has_path = True

            elif name == ":authority":
                authority = value
                headers.append("host", value)

            elif not name.startswith(":"):
                headers.append(name, value)

        if method not in ("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"):
            return None

        if method == "CONNECT":
            if not authority or has_scheme or has_path:
                return None
        else:
            if not method or not target or not has_scheme or scheme not in ("http", "https"):
                return None

        content_length_hdr = headers.get("content-length")
        if asm.body:
            body: bytes | None = bytes(asm.body)
        elif content_length_hdr is not None:
            body = b""
        else:
            body = None

        return Request(client=self.client, scheme=scheme, secure=True, protocol="HTTP/3.0", method=method, target=target or "/", headers=headers, body=body, h2=None, h3=H3Info(connection_id=self.quic.local_cid, stream_id=stream_id), tls=self.tls)

    def _is_websocket_connect(self, raw_headers) -> bool:
        method = protocol = None
        for nameb, valueb in raw_headers:
            name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
            value = valueb.decode("ascii", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb
            if name == ":method":
                method = value
            elif name == ":protocol":
                protocol = value
        return method == "CONNECT" and protocol == "websocket"

    def _build_websocket_request(self, stream_id: int, raw_headers) -> Request | None:
        authority = ""
        scheme: str | None = None
        target: str | None = None
        has_scheme = has_path = False
        headers = Headers({})

        for nameb, valueb in raw_headers:
            name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
            value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb

            if name == ":scheme":
                scheme = value if value in ("http", "https") else "https"
                has_scheme = True
            elif name == ":path":
                target = value
                has_path = True
            elif name == ":authority":
                authority = value
                headers.append("host", value)
            elif name in (":method", ":protocol"):
                continue
            elif not name.startswith(":"):
                headers.append(name, value)

        # RFC 8441 §4: an extended CONNECT must carry :scheme and :path.
        if not authority or not has_scheme or not has_path or scheme not in ("http", "https"):
            return None

        return Request(client=self.client, scheme=scheme, secure=True, protocol="HTTP/3.0", method="GET", target=target or "/", headers=headers, body=None, h2=None, h3=H3Info(connection_id=self.quic.local_cid, stream_id=stream_id), tls=self.tls)

    async def websocket_respond(self, stream_id: int, request: Request):
        subprotocol, deflate = negotiate_websocket(request, self.handler.callback.websocket_subprotocols)

        headers: list[tuple[bytes, bytes]] = [(b":status", b"200")]
        if subprotocol:
            headers.append((b"sec-websocket-protocol", subprotocol.encode("latin-1")))
        if deflate is not None:
            headers.append((b"sec-websocket-extensions", deflate.response_header().encode("latin-1")))

        self.send_headers(stream_id, headers, end_stream=False)
        self.flush()

        transport = H3WebSocketTransport(self, stream_id)
        ws = WebSocket(transport, require_masking=False, subprotocol=subprotocol, deflate=deflate, max_message_size=self.config.max_websocket_message_size if self.handler else None)

        self.handler.create_task(self.websocket_read(stream_id, ws))
        await self.run_websocket(request, ws)

    async def websocket_read(self, stream_id: int, ws: WebSocket):
        queue = self.websocket_streams.get(stream_id)
        if queue is None:
            return

        buf = bytearray()
        max_size = self.config.max_websocket_message_size if self.handler else None

        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.end_queue()
                break

            buf.extend(chunk)
            try:
                frames = parse_frames(buf, max_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                break
            except ValueError:
                ws.close_transport(1009)
                break

            for frame in frames:
                ws.feed_frame(frame)

        self.websocket_streams.pop(stream_id, None)

    async def run_websocket(self, request: Request, ws: WebSocket):
        import traceback

        active = getattr(self.handler, "active_websockets", None)
        if active is not None:
            active.add(ws)
        try:
            await self.handler.callback.on_websocket(request, ws)
        except Exception:
            traceback.print_exc()
        finally:
            if active is not None:
                active.discard(ws)
            if not ws.closed:
                await ws.close(1011)

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
            sent_any = False

            while pending:
                sent_any = True
                if remaining is not None:
                    remaining -= len(pending)

                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                self.send_data(stream_id, pending, end_stream=not nxt)
                self.flush()
                pending = nxt

            if not sent_any:
                self.send_data(stream_id, b"", end_stream=True)
                self.flush()

        finally:
            await loop.run_in_executor(None, fp.close)

    def on_client_event(self, ev):
        if ev.stream_id in self.websocket_streams:
            if isinstance(ev, HeadersReceived):
                status = 0
                subprotocol = None
                for nameb, valueb in ev.headers:
                    name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
                    value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb
                    if name == ":status":
                        try:
                            status = int(value)
                        except ValueError:
                            status = 0
                    elif name == "sec-websocket-protocol":
                        subprotocol = value
                fut = self.websocket_pending.pop(ev.stream_id, None)
                if fut is not None and not fut.done():
                    fut.set_result((status, subprotocol))

            elif isinstance(ev, DataReceived):
                if ev.data:
                    self.websocket_streams[ev.stream_id].put_nowait(ev.data)
                if ev.stream_ended:
                    self.websocket_streams[ev.stream_id].put_nowait(None)
            return

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
        has_body = request.body is not None
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

    async def open_websocket(self, request: Request, *, subprotocols: list[str] | None = None) -> WebSocket:
        # Client-side WebSocket over HTTP/3 via extended CONNECT (RFC 9220).
        stream_id = self.open_request_stream()
        headers = H3.build_websocket_connect_headers(request, self.authority, subprotocols)

        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.websocket_pending[stream_id] = future
        self.websocket_streams[stream_id] = asyncio.Queue()

        self.send_headers(stream_id, headers, end_stream=False)
        self.flush()

        status, subprotocol = await future
        if status != 200:
            self.websocket_streams.pop(stream_id, None)
            raise ConnectionError(f"WebSocket upgrade over HTTP/3 failed: status {status}")

        transport = H3WebSocketTransport(self, stream_id)
        max_size = self.config.max_websocket_message_size if self.handler else None
        ws = WebSocket(transport, require_masking=False, mask_frames=True, subprotocol=subprotocol, deflate=None, max_message_size=max_size)

        asyncio.ensure_future(self.websocket_read(stream_id, ws))
        return ws

    def lost(self, exc: BaseException | None):
        self.fail_all(exc or ConnectionError("connection lost"))

    def close(self):
        self.closed = True

        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        if self.control_stream_id is not None:
            try:
                goaway_id = max(0, self.last_processed_stream_id)
                goaway_payload = encode_uint_var(goaway_id)
                self.quic.send_stream_data(self.control_stream_id, H3.encode_frame(FRAME_GOAWAY, goaway_payload), end_stream=False)
                self.flush()
            except Exception:
                pass

        if self.protocol.transport is not None:
            self.protocol.transport.close()

    async def aclose(self):
        self.close()

class H3Protocol(asyncio.DatagramProtocol):
    def __init__(self, handler=None, *, is_client: bool = False, connection: H3Connection | None = None, max_connections: int = 4096, quic_tls_context: QuicTLSServerContext | None = None, max_connections_per_ip: int = 256):
        self.handler = handler
        self.is_client = is_client
        self.transport: asyncio.DatagramTransport | None = None
        self.connection = connection
        self.connections: dict[tuple, H3Connection] = {}
        self.max_connections = max_connections
        self.quic_tls_context = quic_tls_context
        self.connections_per_ip: dict[str, int] = {}
        self.max_connections_per_ip = max_connections_per_ip
        self.retry_secret = os.urandom(32)  # per-process key for stateless Retry tokens

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
            if len(data) < 1200 or not (data[0] & 0x80):
                return

            if data[1:5] != b"\x00\x00\x00\x01":
                try:
                    hdr = parse_long_header(data, 0)
                    vn = build_version_negotiation(hdr.destination_cid, hdr.source_cid)

                    if self.transport is not None:
                        self.transport.sendto(vn, addr)
                except Exception:
                    pass
                return

            if (data[0] & 0xF0) != 0xC0:
                return

            if len(self.connections) >= self.max_connections:
                return

            ip = addr[0] if isinstance(addr, tuple) else str(addr)
            if self.connections_per_ip.get(ip, 0) >= self.max_connections_per_ip:
                return

            # Optional address validation via Retry (RFC 9000 §8.1).
            retry_enabled = self.handler is not None and getattr(self.handler.config, "quic_retry", False)
            if retry_enabled:
                try:
                    hdr = parse_long_header(data, 0)
                except Exception:
                    return
                if not hdr.token:
                    try:
                        retry = QUICConnection.create_retry(data, self.retry_secret)
                        if self.transport is not None:
                            self.transport.sendto(retry, addr)
                    except Exception:
                        pass
                    return

            retry_secret = self.retry_secret if retry_enabled else None
            try:
                if self.quic_tls_context is not None:
                    quic = QUICConnection.create_server(data, lambda tp: self.quic_tls_context.connection(transport_params=tp), retry_secret=retry_secret)
                else:
                    quic = QUICConnection.create_server(data, lambda tp: QuicTLS.for_server(self.handler.config.tls, transport_params=tp), retry_secret=retry_secret)
            except Exception:
                return

            conn = H3Connection(quic, self, is_client=False, addr=addr)
            self.connections[addr] = conn
            self.connections_per_ip[ip] = self.connections_per_ip.get(ip, 0) + 1

        if conn.receive_datagram(data):
            self._reap(addr)

    def _reap(self, addr):
        if self.connections.pop(addr, None) is None:
            return

        ip = addr[0] if isinstance(addr, tuple) else str(addr)
        count = self.connections_per_ip.get(ip, 1)

        if count <= 1:
            self.connections_per_ip.pop(ip, None)
        else:
            self.connections_per_ip[ip] = count - 1

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
