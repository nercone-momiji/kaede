from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import Literal
from dataclasses import dataclass

import h2.config
import h2.connection
import h2.errors
import h2.events
from h2.settings import SettingCodes

from ..models import Request, Response, Headers, RequestStream, ResponseStream
from ..tls import TLSInfo
from ..process import process_request
from ..websocket import WebSocket, WebSocketProtocolError, parse_frames
from ..handler.common import StreamState, consume_response, dispatch_event, negotiate_websocket
from ..handler.tcp import TCPProtocol

H2_FORBIDDEN_HEADERS = ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection")

@dataclass
class H2Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H2WSUpgrade:
    stream_id: int
    request: Request

class H2:
    """Stateless HTTP/2 protocol helpers (header (de)composition).

    Per-connection state is owned by :class:`H2Connection`.
    """

    FORBIDDEN_HEADERS = H2_FORBIDDEN_HEADERS

    @staticmethod
    def build_response_headers(response: Response) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [(":status", str(response.status_code))]

        for name, value in response.headers.items():
            lname = name.lower()

            if lname in H2_FORBIDDEN_HEADERS:
                continue

            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue

            headers.append((lname, value))

        return headers

    @staticmethod
    def build_request_headers(request: Request, authority: str) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [
            (":method", request.method),
            (":scheme", request.scheme),
            (":authority", authority),
            (":path", request.target),
        ]

        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H2_FORBIDDEN_HEADERS or lname in ("host", "content-length"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname, value))

        return headers

    @staticmethod
    def build_connect_websocket_headers(request: Request, authority: str, subprotocols: list[str] | None = None, extensions: str | None = None) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", request.scheme),
            (":authority", authority),
            (":path", request.target),
            ("sec-websocket-version", "13"),
        ]
        if subprotocols:
            headers.append(("sec-websocket-protocol", ", ".join(subprotocols)))
        if extensions:
            headers.append(("sec-websocket-extensions", extensions))

        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H2_FORBIDDEN_HEADERS or lname in ("host", "content-length") or lname.startswith("sec-websocket"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname, value))

        return headers

class H2Connection:
    """Manages a single HTTP/2 connection (server or client side).

    Wraps the ``h2`` state machine, drives stream send/receive flow control and
    bridges requests/responses (and CONNECT-based WebSockets) to the transport
    owned by an :class:`H2Protocol`. Stateless helpers live in :class:`H2`.
    """

    def __init__(self, protocol, is_client: bool = False, *, key: tuple | None = None, authority: str | None = None):
        self.protocol = protocol
        self.handler = protocol.handler
        self.is_client = is_client

        self.key = key
        self.authority = authority
        self.mode = "h2"
        self.multiplexed = True

        config = self.handler.config

        self.connection_id = b"" if is_client else os.urandom(8)
        self.client_side = is_client
        self.connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=is_client, header_encoding="utf-8"))

        self.request_streams: dict[int, RequestStream] = {}
        self.response_streams: dict[int, ResponseStream] = {}
        self.websocket_streams: dict[int, asyncio.Queue[bytes | None]] = {}

        self.reset_count = 0

        self.max_body_size = config.max_body_size
        self.max_stream_resets = getattr(config, "max_stream_resets", 1000)
        self.max_concurrent_streams = config.max_concurrent_streams

        self.send_buffers: dict[int, bytearray] = {}
        self.send_ended: dict[int, bool] = {}

        self.flow_control_event = asyncio.Event()

        # client response demux
        self.streams: dict[int, StreamState] = {}
        self.settings: asyncio.Event = asyncio.Event()

        # server keepalive
        self.inflight: int = 0
        self.keep_alive: bool = True
        self.keep_alive_handle: asyncio.TimerHandle | None = None

    @property
    def transport(self):
        return self.protocol.transport

    @property
    def config(self):
        return self.handler.config

    @property
    def client(self):
        return self.protocol.client

    @property
    def secure(self) -> bool:
        return self.protocol.secure

    @property
    def tls(self) -> TLSInfo | None:
        return self.protocol.tls

    # --- lifecycle ---

    def start(self):
        if self.transport is not None:
            self.transport.write(self.initiate())
        if not self.is_client:
            self.reset_keepalive()

    def feed(self, data: bytes):
        if self.is_client:
            self.feed_client(data)
        else:
            self.feed_server(data)

    def lost(self, exc: BaseException | None):
        if self.is_client:
            self.client_lost(exc)
        else:
            self.server_lost(exc)

    def is_open(self) -> bool:
        return self.transport is not None and not self.protocol.closed

    def close(self):
        self.protocol.close()

    # --- server keepalive ---

    def reset_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        if self.transport is not None and self.keep_alive and self.inflight == 0:
            self.keep_alive_handle = asyncio.get_running_loop().call_later(self.config.keepalive_timeout, self.on_keepalive_timeout)

    def cancel_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

    def on_keepalive_timeout(self):
        self.keep_alive_handle = None
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    # --- h2 state machine ---

    def initiate(self) -> bytes:
        self.connection.initiate_connection()
        if self.client_side:
            self.connection.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams})
        else:
            self.connection.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1, SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams})
        return self.connection.data_to_send()

    def receive(self, data: bytes, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> tuple[bytes, list[Request], list[H2WSUpgrade], bool]:
        closed = False
        events = self.connection.receive_data(data)
        completed: list[Request] = []
        websocket_upgrades: list[H2WSUpgrade] = []

        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                stream = RequestStream(scheme=scheme)
                websocket_protocol: str | None = None

                for name, value in event.headers:
                    if name == ":method":
                        stream.method = value
                    elif name == ":path":
                        stream.target = value
                    elif name == ":scheme":
                        stream.scheme = value
                    elif name == ":authority":
                        stream.authority = value
                        stream.headers.append("host", value)
                    elif name == ":protocol":
                        websocket_protocol = value
                    elif not name.startswith(":"):
                        stream.headers.append(name, value)

                if stream.method == "CONNECT" and websocket_protocol == "websocket":
                    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
                    self.websocket_streams[event.stream_id] = queue
                    request = Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method="GET", target=stream.target, headers=stream.headers, body=None, h2=H2Info(connection_id=self.connection_id, stream_id=event.stream_id), h3=None, tls=tls)
                    websocket_upgrades.append(H2WSUpgrade(stream_id=event.stream_id, request=request))
                    continue

                self.request_streams[event.stream_id] = stream
                if event.stream_ended:
                    completed.append(self.finalize_request(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in self.websocket_streams:
                    if event.data:
                        self.websocket_streams[event.stream_id].put_nowait(event.data)

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if event.stream_ended:
                        self.websocket_streams[event.stream_id].put_nowait(None)
                        del self.websocket_streams[event.stream_id]

                else:
                    stream = self.request_streams.get(event.stream_id)
                    if stream is not None:
                        stream.body.extend(event.data)

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if stream is not None and len(stream.body) > self.max_body_size:
                        self.request_streams.pop(event.stream_id, None)

                        try:
                            self.connection.reset_stream(event.stream_id, error_code=h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
                        except Exception:
                            pass

                    elif event.stream_ended and event.stream_id in self.request_streams:
                        completed.append(self.finalize_request(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]

                elif event.stream_id in self.request_streams:
                    completed.append(self.finalize_request(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamReset):
                self.reset_count += 1

                if self.reset_count > self.max_stream_resets:
                    closed = True

                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]

                else:
                    self.request_streams.pop(event.stream_id, None)

                self.discard_send(event.stream_id)

            elif isinstance(event, h2.events.WindowUpdated):
                if event.stream_id == 0:
                    for sid in list(self.send_buffers.keys()):
                        self.pump(sid)
                else:
                    self.pump(event.stream_id)

            elif isinstance(event, h2.events.ConnectionTerminated):
                for queue in self.websocket_streams.values():
                    queue.put_nowait(None)

                self.websocket_streams.clear()
                self.request_streams.clear()
                self.send_buffers.clear()
                self.send_ended.clear()

                closed = True

        for sid in list(self.send_buffers.keys()):
            self.pump(sid)

        self.flow_control_event.set()

        return self.connection.data_to_send(), completed, websocket_upgrades, closed

    def enqueue(self, stream_id: int, data: bytes, end_stream: bool):
        buffer = self.send_buffers.get(stream_id)

        if buffer is None:
            buffer = bytearray()
            self.send_buffers[stream_id] = buffer

        buffer.extend(data)

        if end_stream:
            self.send_ended[stream_id] = True

    def discard_send(self, stream_id: int):
        self.send_buffers.pop(stream_id, None)
        self.send_ended.pop(stream_id, None)

    def pump(self, stream_id: int):
        buffer = self.send_buffers.get(stream_id)
        ended = self.send_ended.get(stream_id, False)

        if buffer is None:
            if ended:
                try:
                    self.connection.end_stream(stream_id)
                except Exception:
                    pass
                self.send_ended.pop(stream_id, None)
            return

        try:
            while buffer:
                window = self.connection.local_flow_control_window(stream_id)
                if window <= 0:
                    return

                max_frame = self.connection.max_outbound_frame_size or 16384
                size = min(len(buffer), window, max_frame)

                chunk = bytes(buffer[:size])
                del buffer[:size]

                end = ended and not buffer
                self.connection.send_data(stream_id, chunk, end_stream=end)

                if end:
                    self.discard_send(stream_id)
                    return

            if ended:
                self.connection.end_stream(stream_id)
                self.discard_send(stream_id)

        except Exception:
            self.discard_send(stream_id)

    def stream_buffered(self, stream_id: int) -> int:
        buf = self.send_buffers.get(stream_id)
        return len(buf) if buf else 0

    def finalize_request(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.request_streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=H2Info(connection_id=self.connection_id, stream_id=stream_id), h3=None, tls=tls)

    def send_response(self, stream_id: int, response: Response) -> tuple[bytes, os.PathLike | None]:
        headers = H2.build_response_headers(response)

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            self.enqueue(stream_id, response.body, end_stream=True)
            self.pump(stream_id)
            return self.connection.data_to_send(), None

        elif response.body is not None:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            return self.connection.data_to_send(), response.body

        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
            return self.connection.data_to_send(), None

    def send_response_headers(self, stream_id: int, response: Response) -> bytes:
        self.connection.send_headers(stream_id, H2.build_response_headers(response), end_stream=False)
        return self.connection.data_to_send()

    def send_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> bytes:
        self.enqueue(stream_id, chunk, end_stream)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def send_goaway(self, error_code: int = 0) -> bytes:
        self.connection.close_connection(error_code=error_code)
        return self.connection.data_to_send()

    def websocket_accept(self, stream_id: int, subprotocol: str | None = None, extensions: str | None = None) -> bytes:
        headers = [(":status", "200")]

        if subprotocol:
            headers.append(("sec-websocket-protocol", subprotocol))

        if extensions:
            headers.append(("sec-websocket-extensions", extensions))

        self.connection.send_headers(stream_id, headers, end_stream=False)
        return self.connection.data_to_send()

    def websocket_send(self, stream_id: int, data: bytes) -> bytes:
        self.enqueue(stream_id, data, end_stream=False)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def websocket_close(self, stream_id: int) -> bytes:
        self.websocket_streams.pop(stream_id, None)
        self.send_ended[stream_id] = True
        self.pump(stream_id)
        return self.connection.data_to_send()

    def send_request(self, request: Request, authority: str) -> tuple[int, bytes]:
        stream_id = self.connection.get_next_available_stream_id()
        headers = H2.build_request_headers(request, authority)
        has_body = bool(request.body)

        self.connection.send_headers(stream_id, headers, end_stream=not has_body)

        if has_body:
            self.enqueue(stream_id, request.body, end_stream=True)
            self.pump(stream_id)

        return stream_id, self.connection.data_to_send()

    def send_connect_websocket(self, request: Request, authority: str, subprotocols: list[str] | None = None, extensions: str | None = None) -> tuple[int, bytes]:
        stream_id = self.connection.get_next_available_stream_id()
        headers = H2.build_connect_websocket_headers(request, authority, subprotocols, extensions)

        self.connection.send_headers(stream_id, headers, end_stream=False)

        queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.websocket_streams[stream_id] = queue

        return stream_id, self.connection.data_to_send()

    def send_body_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> bytes:
        self.enqueue(stream_id, chunk, end_stream)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def receive_response(self, data: bytes) -> tuple[bytes, list[tuple], bool]:
        closed = False
        events = self.connection.receive_data(data)
        out_events: list[tuple] = []

        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                status = 0
                headers = Headers({})
                for name, value in event.headers:
                    if name == ":status":
                        try:
                            status = int(value)
                        except ValueError:
                            status = 0
                    elif not name.startswith(":"):
                        headers.append(name, value)

                out_events.append(("response", event.stream_id, status, headers))
                if event.stream_ended:
                    out_events.append(("end", event.stream_id))

            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in self.websocket_streams:
                    if event.data:
                        self.websocket_streams[event.stream_id].put_nowait(event.data)

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if event.stream_ended:
                        self.websocket_streams[event.stream_id].put_nowait(None)
                        del self.websocket_streams[event.stream_id]

                else:
                    if event.data:
                        out_events.append(("data", event.stream_id, event.data))

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if event.stream_ended:
                        out_events.append(("end", event.stream_id))

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]
                else:
                    out_events.append(("end", event.stream_id))

            elif isinstance(event, h2.events.StreamReset):
                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]
                else:
                    out_events.append(("reset", event.stream_id))

                self.discard_send(event.stream_id)

            elif isinstance(event, h2.events.RemoteSettingsChanged):
                out_events.append(("settings", 0))

            elif isinstance(event, h2.events.WindowUpdated):
                if event.stream_id == 0:
                    for sid in list(self.send_buffers.keys()):
                        self.pump(sid)
                else:
                    self.pump(event.stream_id)

            elif isinstance(event, h2.events.ConnectionTerminated):
                for queue in self.websocket_streams.values():
                    queue.put_nowait(None)

                self.websocket_streams.clear()
                self.send_buffers.clear()
                self.send_ended.clear()

                closed = True
                out_events.append(("close", 0))

        for sid in list(self.send_buffers.keys()):
            self.pump(sid)

        self.flow_control_event.set()

        return self.connection.data_to_send(), out_events, closed

    # --- server: receive + response ---

    def feed_server(self, data: bytes):
        if self.transport is None:
            return

        self.reset_keepalive()

        out, requests, websocket_upgrades, closed = self.receive(data, client=self.client, secure=self.secure, tls=self.tls)
        if out:
            self.transport.write(out)

        for request in requests:
            self.handler.create_task(self.respond(request))

        for websocket_upgrade in websocket_upgrades:
            self.handler.create_task(self.websocket_respond(websocket_upgrade))

        if closed:
            goaway = self.send_goaway()
            if goaway and self.transport is not None:
                self.transport.write(goaway)
            if self.transport is not None:
                self.transport.close()

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

    async def respond(self, request: Request):
        if self.transport is None or request.h2 is None:
            return

        self.inflight += 1
        self.cancel_keepalive()
        try:
            response = await process_request(request, callback=self.handler.callback, config=self.config)

            if "h3" in self.config.protocols and self.config.bind_quic:
                _, _, h3_port = self.config.bind_quic[0].rpartition(':')
                response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

            if response.is_streaming:
                await self.stream(request.h2.stream_id, response)
                return

            out, alt_body = self.send_response(request.h2.stream_id, response)

            if out:
                self.transport.write(out)

            if alt_body is not None:
                await self.send_file(request.h2.stream_id, alt_body, response.file_range)

        finally:
            self.inflight -= 1
            if self.inflight == 0 and self.transport is not None:
                self.reset_keepalive()

    async def stream(self, stream_id: int, response: Response):
        if self.transport is None:
            return

        out = self.send_response_headers(stream_id, response)
        if out:
            self.transport.write(out)

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None:
                    out = self.send_chunk(stream_id, chunk, end_stream=False)
                    if out:
                        self.transport.write(out)
                    await self.drain_window(stream_id)

        finally:
            if self.transport is not None:
                out = self.send_chunk(stream_id, b"", end_stream=True)
                if out:
                    self.transport.write(out)

    async def send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None):
        if self.transport is None:
            return
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            out = self.send_chunk(stream_id, b"", end_stream=True)
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
            while pending and self.transport is not None:
                if remaining is not None:
                    remaining -= len(pending)
                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                is_last = not nxt
                out = self.send_chunk(stream_id, pending, end_stream=is_last)
                if out and self.transport:
                    self.transport.write(out)
                sent_any = True
                pending = nxt
                await self.drain_window(stream_id)

        finally:
            await loop.run_in_executor(None, fp.close)

        if not sent_any and self.transport is not None:
            out = self.send_chunk(stream_id, b"", end_stream=True)
            if out and self.transport:
                self.transport.write(out)

    async def drain_window(self, stream_id: int):
        while self.transport is not None and not self.transport.is_closing():
            if self.stream_buffered(stream_id) <= self.config.max_stream_buffer_size:
                return

            self.flow_control_event.clear()

            if self.stream_buffered(stream_id) <= self.config.max_stream_buffer_size:
                return

            await self.flow_control_event.wait()

    async def websocket_read(self, stream_id: int, ws: WebSocket):
        queue = self.websocket_streams.get(stream_id)
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
                frames = parse_frames(buf, self.config.max_websocket_message_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                break
            except ValueError:
                ws.close_transport(1009)
                break
            for frame in frames:
                ws.feed_frame(frame)

    async def websocket_respond(self, upgrade: H2WSUpgrade):
        if self.transport is None:
            return

        subprotocol, deflate = negotiate_websocket(upgrade.request, self.handler.callback.websocket_subprotocols)

        out = self.websocket_accept(upgrade.stream_id, subprotocol=subprotocol, extensions=deflate.response_header() if deflate is not None else None)
        if out:
            self.transport.write(out)

        ws_transport = H2WebSocketTransport(self, upgrade.stream_id, self.transport)
        ws = WebSocket(ws_transport, require_masking=False, subprotocol=subprotocol, deflate=deflate, max_message_size=self.config.max_websocket_message_size)

        self.inflight += 1
        self.cancel_keepalive()
        try:
            self.handler.create_task(self.websocket_read(upgrade.stream_id, ws))
            await self.run_websocket(upgrade.request, ws)
        finally:
            self.inflight -= 1
            if self.inflight == 0 and self.transport is not None:
                self.reset_keepalive()

    def server_lost(self, exc: BaseException | None):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        for queue in self.websocket_streams.values():
            queue.put_nowait(None)
        self.flow_control_event.set()

    # --- client: receive + request ---

    def feed_client(self, data: bytes):
        if self.transport is None:
            return

        out, events, closed = self.receive_response(data)
        if out:
            self.transport.write(out)

        for event in events:
            if event[0] == "settings":
                self.settings.set()
                continue
            dispatch_event(self.streams, event)

        if closed:
            self.close()

    async def request(self, request: Request, streaming: bool) -> Response:
        if self.transport is None:
            raise ConnectionError("connection is not available")

        stream_id, out = self.send_request(request, self.authority)
        state = StreamState(asyncio.get_running_loop(), self.config.max_body_size)
        self.streams[stream_id] = state

        if out:
            self.transport.write(out)

        def on_done():
            self.streams.pop(stream_id, None)

        try:
            return await consume_response(state, streaming, "HTTP/2.0", self.config.read_timeout, on_done)
        except BaseException:
            self.streams.pop(stream_id, None)
            raise

    async def websocket(self, request: Request, subprotocols: list[str] | None) -> WebSocket:
        if self.transport is None:
            raise ConnectionError("connection is not available")

        await asyncio.wait_for(self.settings.wait(), self.config.read_timeout)

        stream_id, out = self.send_connect_websocket(request, self.authority, subprotocols)
        state = StreamState(asyncio.get_running_loop(), self.config.max_body_size)
        self.streams[stream_id] = state

        if out:
            self.transport.write(out)

        try:
            status, headers = await asyncio.wait_for(state.header_future, self.config.read_timeout)
        finally:
            self.streams.pop(stream_id, None)

        if status != 200:
            self.discard_send(stream_id)
            raise ConnectionError(f"websocket upgrade rejected with status {status}")

        subprotocol = (headers.get("Sec-WebSocket-Protocol") or "").strip() or None
        ws = WebSocket(H2ClientWSTransport(self, stream_id), require_masking=False, mask_frames=True, subprotocol=subprotocol, max_message_size=self.config.max_websocket_message_size)

        self.handler.create_task(self.websocket_read(stream_id, ws))
        return ws

    def client_lost(self, exc: BaseException | None):
        for queue in self.websocket_streams.values():
            queue.put_nowait(None)
        for state in list(self.streams.values()):
            state.fail(exc or ConnectionError("connection closed"))

class H2WebSocketTransport:
    def __init__(self, connection: H2Connection, stream_id: int, transport):
        self.connection = connection
        self.stream_id = stream_id
        self.transport = transport

    def write(self, data: bytes):
        if self.transport.is_closing():
            return
        out = self.connection.websocket_send(self.stream_id, data)
        if out:
            self.transport.write(out)

    def close(self):
        out = self.connection.websocket_close(self.stream_id)
        if out and not self.transport.is_closing():
            self.transport.write(out)

class H2ClientWSTransport:
    def __init__(self, connection: H2Connection, stream_id: int):
        self.connection = connection
        self.stream_id = stream_id

    def write(self, data: bytes):
        if self.connection.transport is None:
            return
        out = self.connection.send_body_chunk(self.stream_id, data, end_stream=False)
        if out:
            self.connection.transport.write(out)

    def close(self):
        if self.connection.transport is None:
            return
        out = self.connection.websocket_close(self.stream_id)
        if out:
            self.connection.transport.write(out)

class H2Protocol(TCPProtocol):
    """asyncio protocol for HTTP/2 connections with prior knowledge (h2c).

    TLS-terminated HTTP/2 is established through
    :class:`~kaede.handler.tcp.TCPProtocol` after ALPN selects ``h2``.
    """

    def __init__(self, handler, *, is_client: bool = False, tls_context=None, server_name: str | None = None, key: tuple | None = None, authority: str | None = None):
        self._key = key
        self._authority = authority
        super().__init__(is_client=is_client, factory=self._build, tls_context=tls_context, server_name=server_name, handler=handler)

    def _build(self, protocol, alpn):
        return H2Connection(protocol, is_client=self.is_client, key=self._key, authority=self._authority)
