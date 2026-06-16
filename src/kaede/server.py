from __future__ import annotations

import os
import ssl
import signal
import socket
import uvloop
import asyncio
import ipaddress
from typing import Literal
from dataclasses import dataclass, field

from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.server import QuicServer
from aioquic.asyncio.protocol import QuicConnectionProtocol

from .h1 import H1
from .h2 import H2, H2WSUpgrade
from .h3 import H3, H3WSUpgrade
from .tls import TLS, TLSInfo, TLSServerConfig
from .models import Listener, Callback, Request, Response
from .process import process_request
from .websocket import WebSocket, PerMessageDeflate, compute_accept, parse_frames

@dataclass
class Config:
    server_name: str = "Kaede"

    bind_unix:  list[os.PathLike] = field(default_factory=list)
    bind_http:  list[str] = field(default_factory=lambda: ["127.0.0.1:80", "[::1]:80"])
    bind_https: list[str] = field(default_factory=list)
    bind_quic:  list[str] = field(default_factory=list)

    protocols: list[Literal["http/1.1", "h2", "h3"]] = field(default_factory=lambda: ["h3", "h2", "http/1.1"])

    tls: TLSServerConfig = field(default_factory=lambda: TLSServerConfig())

    keepalive_timeout: float = 75

    max_header_size: int = 64 * 1024
    max_body_size: int = 16 * 1024 * 1024

    max_stream_buffer_size: int = 1024 * 1024
    max_pipeline_buffer_len: int = 100
    max_websocket_message_size: int = 4 * 1024 * 1024

    max_concurrent_streams: int = 100
    max_stream_resets: int = 1000

    workers: int = 1
    auto_restart: bool = True
    shutdown_timeout: float = 30

def parse_peername(transport: asyncio.BaseTransport) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    peer = transport.get_extra_info("peername")
    if not peer:
        return (ipaddress.IPv4Address("0.0.0.0"), 0)
    host, port = peer[0], peer[1]
    try:
        return (ipaddress.ip_address(host), int(port))
    except ValueError:
        return (ipaddress.IPv4Address("0.0.0.0"), int(port))

def negotiate_websocket(request: Request, subprotocols: list[str]) -> tuple[str | None, PerMessageDeflate | None]:
    offered_raw = request.headers.get("Sec-WebSocket-Protocol") or ""
    offered = [p.strip() for p in offered_raw.split(",") if p.strip()] if offered_raw else [] # type: ignore
    subprotocol: str | None = next((subprotocol for subprotocol in offered if subprotocol in subprotocols), None)

    ext_raw = request.headers.get("Sec-WebSocket-Extensions") or ""
    deflate = PerMessageDeflate.from_client_offer(ext_raw) if ext_raw else None # type: ignore

    return subprotocol, deflate

class H2WebSocketTransport:
    def __init__(self, h2: H2, stream_id: int, transport: asyncio.Transport):
        self.h2 = h2
        self.stream_id = stream_id
        self.transport = transport

    def write(self, data: bytes):
        if self.transport.is_closing():
            return
        out = self.h2.websocket_send(self.stream_id, data)
        if out:
            self.transport.write(out)

    def close(self):
        out = self.h2.websocket_close(self.stream_id)
        if out and not self.transport.is_closing():
            self.transport.write(out)

class H3WebSocketTransport:
    def __init__(self, h3: H3, stream_id: int, protocol: H3Protocol):
        self.h3 = h3
        self.stream_id = stream_id
        self.protocol = protocol

    def write(self, data: bytes):
        if not data:
            return
        self.h3.websocket_send(self.stream_id, data)
        self.protocol.transmit()

    def close(self):
        self.h3.websocket_close(self.stream_id)
        self.protocol.transmit()

class TCPProtocol(asyncio.Protocol):
    def __init__(self, handler: Handler):
        self.handler = handler

        self.transport: asyncio.Transport | None = None
        self.buffer = bytearray()

        self.websocket: WebSocket | None = None
        self.websocket_buffer: bytearray = bytearray()
        self.websocket_pending: bool = False

        self.client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)
        self.secure: bool = False

        self.h2: H2 | None = None
        self.tls: TLSInfo | None = None

        self.continue_sent: bool = False
        self.reading_paused: bool = False

        self.keep_alive: bool = True
        self.keep_alive_handle: asyncio.TimerHandle | None = None

        self.request_queue: asyncio.Queue[tuple[Request, bool] | None] = asyncio.Queue()
        self.request_consumer: asyncio.Task | None = None

        self.inflight: int = 0

    def reset_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        if self.transport is not None and self.keep_alive and self.websocket is None and self.inflight == 0:
            self.keep_alive_handle = asyncio.get_running_loop().call_later(self.handler.config.keepalive_timeout, self.on_keepalive_timeout)

    def cancel_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

    def on_keepalive_timeout(self):
        self.keep_alive_handle = None

        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport = transport
        self.client = parse_peername(transport)

        if self.handler.shutdown:
            transport.close()
            return

        if isinstance(transport, asyncio.Transport):
            self.handler.active_transports.add(transport)

        ssl_object: ssl.SSLObject | None = transport.get_extra_info("ssl_object")
        if ssl_object is not None:
            self.secure = True
            self.tls = TLS.extract_tls_info(ssl_object)

            if ssl_object.selected_alpn_protocol() == "h2" and "h2" in self.handler.config.protocols:
                self.h2 = H2(connection_id=os.urandom(8), max_body_size=self.handler.config.max_body_size, max_concurrent_streams=self.handler.config.max_concurrent_streams, max_stream_resets=self.handler.config.max_stream_resets)
                self.transport.write(self.h2.initiate())

            elif "http/1.1" not in self.handler.config.protocols:
                self.transport.close()
                return

        else:
            self.secure = self.handler.listener.kind == "https"

        self.reset_keepalive()

    def data_received(self, data: bytes):
        if self.transport is None:
            return

        self.reset_keepalive()

        if self.websocket is not None:
            self.websocket_buffer.extend(data)

            try:
                frames = parse_frames(self.websocket_buffer, self.handler.config.max_websocket_message_size)
            except ValueError:
                self.websocket.close_transport(1009)
                return

            for frame in frames:
                self.websocket.feed_frame(frame)

            return

        if self.websocket_pending:
            self.buffer.extend(data)
            return

        if self.h2 is None and "http/1.1" not in self.handler.config.protocols:
            self.transport.close()
            return

        if self.h2 is not None:
            out, requests, websocket_upgrades, closed = self.h2.receive(data, client=self.client, secure=self.secure, tls=self.tls)
            if out:
                self.transport.write(out)

            for request in requests:
                self.handler.create_task(self.h2_respond(request))

            for websocket_upgrade in websocket_upgrades:
                self.handler.create_task(self.h2_websocket_respond(websocket_upgrade))

            if closed:
                goaway = self.h2.close()
                if goaway:
                    self.transport.write(goaway)
                self.transport.close()

            return

        self.buffer.extend(data)

        while True:
            head_end = self.buffer.find(b"\r\n\r\n")

            if head_end == -1:
                if len(self.buffer) > self.handler.config.max_header_size:
                    self.send_error(431, "Request Header Fields Too Large")
                    self.transport.close()
                return

            if head_end > self.handler.config.max_header_size:
                self.send_error(431, "Request Header Fields Too Large")
                self.transport.close()
                return

            body_start = head_end + 4

            malformed = False
            expect_continue = False

            transfer_encodings: list[bytes] = []
            content_lengths: list[bytes] = []

            for line in bytes(self.buffer[:head_end]).split(b"\r\n")[1:]:
                if line[:1] in (b" ", b"\t"):
                    malformed = True
                    break

                name_b, sep_b, value_b = line.partition(b":")
                if not sep_b:
                    malformed = True
                    break

                name = name_b.strip().lower()
                value = value_b.strip()

                if name == b"transfer-encoding":
                    transfer_encodings.append(value.lower())

                elif name == b"content-length":
                    content_lengths.append(value)

                elif name == b"expect" and value.lower() == b"100-continue":
                    expect_continue = True

            if malformed or len(transfer_encodings) > 1 or len(content_lengths) > 1:
                self.send_error(400, "Bad Request")
                self.transport.close()
                return

            is_chunked = False

            transfer_encoding_raw = transfer_encodings[0] if transfer_encodings else b""
            content_length_raw = content_lengths[0] if content_lengths else None

            if transfer_encoding_raw:
                te_tokens = [t.strip() for t in transfer_encoding_raw.split(b",") if t.strip()]

                if te_tokens[-1:] != [b"chunked"] or te_tokens.count(b"chunked") != 1:
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                is_chunked = True

            if is_chunked and content_length_raw is not None:
                self.send_error(400, "Bad Request")
                self.transport.close()
                return

            if is_chunked:
                try:
                    scan = H1.scan_chunked(bytes(self.buffer[body_start:]), max_body_size=self.handler.config.max_body_size)
                except ValueError:
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                if scan is None:
                    if len(self.buffer) - body_start > self.handler.config.max_body_size:
                        self.send_error(413, "Payload Too Large")
                        self.transport.close()
                        return

                    self.send_continue(expect_continue)
                    return
                consumed = body_start + scan[1]

            elif content_length_raw is not None:
                if not (content_length_raw.isascii() and content_length_raw.isdigit()):
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                expected = int(content_length_raw)
                if expected > self.handler.config.max_body_size:
                    self.send_error(413, "Payload Too Large")
                    self.transport.close()
                    return

                if len(self.buffer) - body_start < expected:
                    self.send_continue(expect_continue)
                    return

                consumed = body_start + expected

            else:
                consumed = body_start

            try:
                request = H1.parse_request(bytes(self.buffer[:consumed]), client=self.client, secure=self.secure, tls=self.tls, max_body_size=self.handler.config.max_body_size)
            except (ValueError, UnicodeDecodeError):
                self.transport.close()
                return

            del self.buffer[:consumed]
            self.continue_sent = False

            keep_alive = not "close" in (request.headers.get("Connection") or "").lower()

            if self.request_consumer is None:
                self.request_consumer = self.handler.create_task(self.h1_consume_requests())

            self.request_queue.put_nowait((request, keep_alive))

            if request.is_websocket_upgrade:
                self.websocket_pending = True
                return

            if not keep_alive:
                return

            if not self.reading_paused and self.request_queue.qsize() >= self.handler.config.max_pipeline_buffer_len:
                self.reading_paused = True
                self.transport.pause_reading()
                return

    def connection_lost(self, exc: BaseException | None):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        transport = self.transport
        self.transport = None

        if transport is not None:
            self.handler.active_transports.discard(transport)

        if self.h2 is not None:
            for queue in self.h2.websocket_streams.values():
                queue.put_nowait(None)
            self.h2.flow_control_event.set()
            self.h2 = None

        if self.websocket is not None and not self.websocket.closed:
            self.websocket.queue.put_nowait(None)

        self.request_queue.put_nowait(None)

        self.buffer.clear()

    def send_continue(self, expect_continue: bool):
        if expect_continue and not self.continue_sent and self.transport is not None and not self.transport.is_closing():
            self.continue_sent = True
            self.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    def send_error(self, status: int, phrase: str):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.write(f"HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("latin-1"))

    async def run_websocket(self, request: Request, ws: WebSocket):
        self.handler.active_websockets.add(ws)
        try:
            await self.handler.callback.on_websocket(request, ws)
        except Exception:
            pass
        finally:
            self.handler.active_websockets.discard(ws)
            if not ws.closed:
                await ws.close(1011)

    async def h1_respond(self, request: Request):
        if self.transport is None:
            return

        if request.is_websocket_upgrade:
            if self.handler.shutdown:
                self.transport.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                self.transport.close()
                return

            await self.h1_websocket_upgrade(request, request.headers.get("Sec-WebSocket-Key", "").strip())
            return

        response = await process_request(request, callback=self.handler.callback, config=self.handler.config)

        if self.handler.shutdown:
            response.headers.set("Connection", "close")
            self.keep_alive = False

        if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
            _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        if response.is_streaming:
            await self.h1_stream(response)
            return

        result = H1.build_response(response)

        if isinstance(result, tuple):
            head, alt_body = result
            self.transport.write(head)

            if alt_body is not None:
                await self.h1_send_file(alt_body, response.file_range)

        else:
            self.transport.write(result)

        if not self.keep_alive:
            self.transport.close()

    async def h1_stream(self, response: Response):
        if self.transport is None:
            return

        self.transport.write(H1.build_response_head(response))

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None:
                    self.transport.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")

        finally:
            if self.transport is not None:
                self.transport.write(b"0\r\n\r\n")
                if not self.keep_alive:
                    self.transport.close()

    async def h1_send_file(self, path: os.PathLike, file_range: tuple[int, int] | None = None):
        if self.transport is None:
            return
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            if self.transport is not None and not self.transport.is_closing():
                self.transport.close()
            return

        try:
            remaining = None
            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            while self.transport is not None:
                size = 65536 if remaining is None else min(65536, remaining)
                if size <= 0:
                    break
                chunk = await loop.run_in_executor(None, fp.read, size)
                if not chunk:
                    break
                self.transport.write(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
        finally:
            await loop.run_in_executor(None, fp.close)

    async def h1_consume_requests(self):
        while True:
            item = await self.request_queue.get()
            if item is None or self.transport is None:
                break

            self.cancel_keepalive()

            request, keep_alive = item
            self.keep_alive = keep_alive

            await self.h1_respond(request)

            if self.websocket is not None:
                break
            if not self.keep_alive or self.transport is None:
                break

            if self.reading_paused and self.request_queue.qsize() < self.handler.config.max_pipeline_buffer_len // 2 and not self.transport.is_closing():
                self.reading_paused = False
                self.transport.resume_reading()

            self.reset_keepalive()

    async def h1_websocket_upgrade(self, request: Request, ws_key: str):
        if self.transport is None:
            return

        subprotocol, deflate = negotiate_websocket(request, self.handler.callback.websocket_subprotocols)
        accept = compute_accept(ws_key)

        lines = [
            b"HTTP/1.1 101 Switching Protocols\r\n",
            b"Upgrade: websocket\r\n",
            b"Connection: Upgrade\r\n",
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
        ]
        if subprotocol:
            lines.append(b"Sec-WebSocket-Protocol: " + subprotocol.encode() + b"\r\n")
        if deflate is not None:
            lines.append(b"Sec-WebSocket-Extensions: " + deflate.response_header().encode() + b"\r\n")
        lines.append(b"\r\n")

        self.transport.write(b"".join(lines))
        ws = WebSocket(self.transport, subprotocol=subprotocol, deflate=deflate, max_message_size=self.handler.config.max_websocket_message_size)
        self.websocket = ws

        self.websocket_buffer = self.buffer
        self.buffer = bytearray()
        self.websocket_pending = False

        self.handler.create_task(self.run_websocket(request, ws))

        if self.websocket_buffer:
            try:
                frames = parse_frames(self.websocket_buffer, self.handler.config.max_websocket_message_size)
            except ValueError:
                ws.close_transport(1009)
                return
            for frame in frames:
                ws.feed_frame(frame)

    async def h2_respond(self, request: Request):
        if self.transport is None or self.h2 is None or request.h2 is None:
            return

        self.inflight += 1
        self.cancel_keepalive()
        try:
            response = await process_request(request, callback=self.handler.callback, config=self.handler.config)

            if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
                _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
                response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

            if response.is_streaming:
                await self.h2_stream(request.h2.stream_id, response)
                return

            out, alt_body = self.h2.send_response(request.h2.stream_id, response)

            if out:
                self.transport.write(out)

            if alt_body is not None:
                await self.h2_send_file(request.h2.stream_id, alt_body, response.file_range)

        finally:
            self.inflight -= 1
            if self.inflight == 0 and self.transport is not None:
                self.reset_keepalive()

    async def h2_stream(self, stream_id: int, response: Response):
        if self.transport is None or self.h2 is None:
            return

        out = self.h2.send_response_headers(stream_id, response)
        if out:
            self.transport.write(out)

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None and self.h2 is not None:
                    out = self.h2.send_chunk(stream_id, chunk, end_stream=False)
                    if out:
                        self.transport.write(out)
                    await self.h2_drain_window(stream_id)

        finally:
            if self.h2 is not None and self.transport is not None:
                out = self.h2.send_chunk(stream_id, b"", end_stream=True)
                if out:
                    self.transport.write(out)

    async def h2_send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None):
        if self.transport is None or self.h2 is None:
            return
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            out = self.h2.send_chunk(stream_id, b"", end_stream=True)
            if out and self.transport is not None:
                self.transport.write(out)
            return

        sent_any = False
        try:
            remaining = None
            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            pending = await loop.run_in_executor(None, fp.read, 65536 if remaining is None else min(65536, remaining))
            while pending and self.transport is not None and self.h2 is not None:
                if remaining is not None:
                    remaining -= len(pending)
                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                is_last = not nxt
                out = self.h2.send_chunk(stream_id, pending, end_stream=is_last)
                if out and self.transport:
                    self.transport.write(out)
                sent_any = True
                pending = nxt
                await self.h2_drain_window(stream_id)

        finally:
            await loop.run_in_executor(None, fp.close)

        if not sent_any and self.h2 is not None:
            out = self.h2.send_chunk(stream_id, b"", end_stream=True)
            if out and self.transport:
                self.transport.write(out)

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

    async def h2_websocket_respond(self, upgrade: H2WSUpgrade):
        if self.transport is None or self.h2 is None:
            return

        subprotocol, deflate = negotiate_websocket(upgrade.request, self.handler.callback.websocket_subprotocols)

        out = self.h2.websocket_accept(upgrade.stream_id, subprotocol=subprotocol, extensions=deflate.response_header() if deflate is not None else None)
        if out:
            self.transport.write(out)

        ws_transport = H2WebSocketTransport(self.h2, upgrade.stream_id, self.transport)
        ws = WebSocket(ws_transport, require_masking=False, subprotocol=subprotocol, deflate=deflate, max_message_size=self.handler.config.max_websocket_message_size)

        self.inflight += 1
        self.cancel_keepalive()
        try:
            self.handler.create_task(self.h2_websocket_read(upgrade.stream_id, ws))
            await self.run_websocket(upgrade.request, ws)
        finally:
            self.inflight -= 1
            if self.inflight == 0 and self.transport is not None:
                self.reset_keepalive()

    async def h2_drain_window(self, stream_id: int):
        while self.h2 is not None and self.transport is not None and not self.transport.is_closing():
            if self.h2.stream_buffered(stream_id) <= self.handler.config.max_stream_buffer_size:
                return

            self.h2.flow_control_event.clear()

            if self.h2.stream_buffered(stream_id) <= self.handler.config.max_stream_buffer_size:
                return

            await self.h2.flow_control_event.wait()

H1Protocol = TCPProtocol
H2Protocol = TCPProtocol

class H3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, handler: Handler, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler
        self.client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)

        self.h3: H3 | None = None
        self.tls: TLSInfo | None = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted) and self.tls is None:
            self.tls = TLS.extract_tls_info_h3(self._quic)

        if self.h3 is None:
            self.h3 = H3(self._quic, connection_id=self._quic.host_cid, max_body_size=self.handler.config.max_body_size)
            self.client = parse_peername(self._transport)

        requests, websocket_upgrades = self.h3.handle_event(event, client=self.client, secure=True, tls=self.tls)

        for request in requests:
            self.handler.create_task(self.respond(request))

        for websocket_upgrade in websocket_upgrades:
            self.handler.create_task(self.websocket_response(websocket_upgrade))

    async def respond(self, request: Request):
        if self.h3 is None or request.h3 is None:
            return

        response = await process_request(request, callback=self.handler.callback, config=self.handler.config)

        if response.is_streaming:
            await self.stream(request.h3.stream_id, response)
            return

        alt_body = self.h3.send(request.h3.stream_id, response)

        if alt_body is not None:
            await self.send_file(request.h3.stream_id, alt_body, response.file_range)

        else:
            self.transmit()

    async def stream(self, stream_id: int, response: Response):
        if self.h3 is None:
            return

        self.h3.send_headers_only(stream_id, response)
        self.transmit()

        try:
            async for chunk in response.body:
                if chunk and self.h3 is not None:
                    self.h3.send_chunk(stream_id, chunk, end_stream=False)
                    self.transmit()

        finally:
            if self.h3 is not None:
                self.h3.send_chunk(stream_id, b"", end_stream=True)
                self.transmit()

    async def send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None):
        if self.h3 is None:
            return
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            self.h3.send_chunk(stream_id, b"", end_stream=True)
            self.transmit()
            return

        sent_any = False
        try:
            remaining = None
            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            pending = await loop.run_in_executor(None, fp.read, 65536 if remaining is None else min(65536, remaining))
            while pending and self.h3 is not None:
                if remaining is not None:
                    remaining -= len(pending)
                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                is_last = not nxt
                self.h3.send_chunk(stream_id, pending, end_stream=is_last)
                self.transmit()
                sent_any = True
                pending = nxt

        finally:
            await loop.run_in_executor(None, fp.close)

        if not sent_any and self.h3 is not None:
            self.h3.send_chunk(stream_id, b"", end_stream=True)
            self.transmit()

    async def websocket_response(self, upgrade: H3WSUpgrade):
        if self.h3 is None:
            return

        subprotocol, deflate = negotiate_websocket(upgrade.request, self.handler.callback.websocket_subprotocols)

        self.h3.ws_accept(upgrade.stream_id, subprotocol=subprotocol, extensions=deflate.response_header() if deflate is not None else None)
        self.transmit()

        ws_transport = H3WebSocketTransport(self.h3, upgrade.stream_id, self)
        ws = WebSocket(ws_transport, require_masking=False, subprotocol=subprotocol, deflate=deflate, max_message_size=self.handler.config.max_websocket_message_size)

        self.handler.create_task(self.websocket_read(upgrade.stream_id, ws))

        request = upgrade.request
        self.handler.active_websockets.add(ws)

        try:
            await self.handler.callback.on_websocket(request, ws)
        except Exception:
            pass

        finally:
            self.handler.active_websockets.discard(ws)
            if not ws.closed:
                await ws.close(1011)

    async def websocket_read(self, stream_id: int, ws: WebSocket):
        if self.h3 is None:
            return

        queue = self.h3.websocket_streams.get(stream_id)
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

class Handler:
    def __init__(self, listener: Listener, callback: Callback, config: Config):
        self.listener = listener
        self.callback = callback
        self.config = config
        self.shutdown = False

        self.tcp_server: asyncio.base_events.Server | None = None
        self.quic_server: QuicServer = None

        self.active_tasks: set[asyncio.Task] = set()
        self.active_transports: set[asyncio.Transport] = set()
        self.active_websockets: set[WebSocket] = set()

    def create_task(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.active_tasks.add(task)
        task.add_done_callback(self.active_tasks.discard)
        return task

    async def start(self):
        loop = asyncio.get_running_loop()
        kind = self.listener.kind

        if kind in ("http", "unix"):
            self.tcp_server = await loop.create_server(lambda: TCPProtocol(self), sock=self.listener.sock)

        elif kind == "https":
            ssl_context = TLS.from_server_config(self.config).context
            self.tcp_server = await loop.create_server(lambda: TCPProtocol(self), sock=self.listener.sock, ssl=ssl_context)

        elif kind == "quic":
            quic_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_datagram_frame_size=65536)
            if self.config.tls.certfile:
                quic_config.load_cert_chain(self.config.tls.certfile, self.config.tls.keyfile)

            _, self.quic_server = await loop.create_datagram_endpoint(lambda: QuicServer(configuration=quic_config, create_protocol=lambda *a, **kw: H3Protocol(*a, handler=self, **kw)), sock=self.listener.sock)

        else:
            raise ValueError(f"unsupported listener kind: {kind!r}")

    async def stop(self):
        if self.tcp_server is not None:
            self.tcp_server.close()
            try:
                await self.tcp_server.wait_closed()
            except Exception:
                pass
            self.tcp_server = None

        if self.quic_server is not None:
            self.quic_server.close()
            self.quic_server = None

    async def drain(self, timeout: float):
        self.shutdown = True

        if self.tcp_server is not None:
            self.tcp_server.close()

        for websocket in list(self.active_websockets):
            if not websocket.closed:
                try:
                    await websocket.close(1001, "Server shutdown")
                except Exception:
                    pass

        tasks = list(self.active_tasks)
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=timeout)

            for task in pending:
                task.cancel()

            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        for transport in list(self.active_transports):
            if not transport.is_closing():
                transport.close()

class Server:
    def __init__(self, callback: Callback, config: Config | None = None):
        self.callback = callback
        self.config = config or Config()

    def bind_unix(self, path: os.PathLike) -> socket.socket:
        if os.path.exists(path):
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(os.fspath(path))
        sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def bind_socket(self, host: str, port: int, type: socket.SocketKind) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        if type == socket.SOCK_STREAM:
            sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock

    def parse_host_port(self, value: str) -> tuple[str, int]:
        host, sep, port = value.rpartition(":")
        if not sep:
            raise ValueError(f"invalid bind address {value!r}: expected 'host:port'")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return host, int(port)

    def listeners(self, *, include_quic: bool = True) -> list[Listener]:
        listeners: list[Listener] = []

        h1_enabled = "http/1.1" in self.config.protocols
        h2_enabled = "h2" in self.config.protocols
        h3_enabled = "h3" in self.config.protocols

        if h1_enabled:
            for path in self.config.bind_unix:
                listeners.append(Listener(self.bind_unix(path), "unix"))

            for value in self.config.bind_http:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "http"))

        if h1_enabled or h2_enabled:
            for value in self.config.bind_https:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_STREAM), "https"))

        if h3_enabled and include_quic:
            listeners.extend(self.quic_listeners())

        return listeners

    def quic_listeners(self) -> list[Listener]:
        listeners: list[Listener] = []
        if "h3" in self.config.protocols:
            for value in self.config.bind_quic:
                host, port = self.parse_host_port(value)
                listeners.append(Listener(self.bind_socket(host, port, socket.SOCK_DGRAM), "quic"))
        return listeners

    def run(self):
        workers = self.config.workers if self.config.workers > 0 else (os.cpu_count() or 1)

        if workers == 1:
            uvloop.run(self.serve(self.listeners()))
            return

        if not hasattr(os, "fork"):
            raise RuntimeError("multiprocessing requires a Unix platform (os.fork not available)")

        alive: set[int] = set()
        shutting_down = False

        shared = self.listeners(include_quic=False)

        def spawn_worker() -> int:
            pid = os.fork()
            if pid == 0:
                try:
                    uvloop.run(self.serve(shared + self.quic_listeners()))
                except KeyboardInterrupt:
                    pass
                finally:
                    os._exit(0)
            alive.add(pid)
            return pid

        for _ in range(workers):
            spawn_worker()

        def forward_signal(signum, frame):
            nonlocal shutting_down
            shutting_down = True
            for pid in list(alive):
                try:
                    os.kill(pid, signum)
                except ProcessLookupError:
                    pass

        signal.signal(signal.SIGINT, forward_signal)
        signal.signal(signal.SIGTERM, forward_signal)

        try:
            while alive:
                try:
                    pid, _ = os.wait()
                    alive.discard(pid)

                    if not shutting_down and self.config.auto_restart:
                        spawn_worker()

                except ChildProcessError:
                    break

        finally:
            for pid in alive:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    async def serve(self, listeners: list[Listener] | None = None):
        handlers = [Handler(listener, self.callback, self.config) for listener in (listeners if listeners is not None else self.listeners())]

        for handler in handlers:
            await handler.start()

        loop = asyncio.get_running_loop()
        stop = loop.create_future()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set_result, None)

        try:
            await stop
        finally:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)

            await asyncio.gather(*[handler.drain(self.config.shutdown_timeout) for handler in handlers], return_exceptions=True)

            for handler in handlers:
                await handler.stop()
