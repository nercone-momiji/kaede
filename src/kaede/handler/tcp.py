from __future__ import annotations

import asyncio
import ipaddress
from typing import Callable

from ..tls import TLS, TLSContext, TLSInfo
from .common import parse_peername, MAX_RESPONSE_HEADER_SIZE
from .tls_transport import TLSTransport, tls_start, tls_feed
from ..websocket import WebSocket, WebSocketProtocolError, parse_frames

ConnectionFactory = Callable[["TCPProtocol", "str | None"], "object | None"]

class TCPProtocol(asyncio.Protocol):
    """Generic TCP/TLS asyncio protocol.

    Owns the OS transport, performs the optional TLS handshake and, once the
    application protocol is known (immediately for plaintext, after the TLS
    handshake/ALPN otherwise), delegates all byte processing to a connection
    object produced by ``factory``. The connection object is expected to expose
    ``start()``, ``feed(data)`` and ``lost(exc)``.
    """

    def __init__(self, *, is_client: bool, factory: ConnectionFactory, tls_context: TLSContext | None = None, server_name: str | None = None, handler=None):
        self.is_client = is_client
        self.factory = factory
        self.tls_context = tls_context
        self.server_name = server_name
        self.handler = handler

        self.transport: asyncio.Transport | TLSTransport | None = None
        self.raw_transport: asyncio.Transport | None = None
        self.tls_engine: TLS | None = None
        self.tls_ready = False

        self.secure: bool = False
        self.tls: TLSInfo | None = None
        self.client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)

        self.connection = None
        self.closed = False
        self.ready: asyncio.Future | None = asyncio.get_running_loop().create_future() if is_client else None

    def connection_made(self, transport: asyncio.BaseTransport):
        self.raw_transport = transport
        self.transport = transport
        self.client = parse_peername(transport)

        if not self.is_client and self.handler is not None and getattr(self.handler, "shutdown", False):
            transport.close()
            return

        if not self.is_client and self.handler is not None and isinstance(transport, asyncio.Transport):
            self.handler.active_transports.add(transport)

        if self.tls_context is not None:
            self.tls_engine = self.tls_context.connection(self.server_name)
            self.transport = TLSTransport(transport, self.tls_engine)
            if self.is_client:
                try:
                    tls_start(self.tls_engine, transport)
                except Exception as exc:
                    self.fail_ready(exc)
                    transport.close()
            return

        self.establish(None)

    def establish(self, alpn: str | None):
        if self.tls_engine is not None:
            self.secure = True
            self.tls = self.tls_engine.info()

        connection = self.factory(self, alpn)

        if connection is None:
            self.close()
            self.fail_ready(ConnectionError("no compatible application protocol negotiated"))
            return

        self.connection = connection
        connection.start()
        self.set_ready()

    def data_received(self, data: bytes):
        if self.transport is None:
            return

        if self.tls_engine is None:
            if self.connection is not None:
                self.connection.feed(data)
            return

        engine = self.tls_engine
        try:
            became_ready, plaintext = tls_feed(engine, self.raw_transport, data)
        except Exception as exc:
            self.fail_ready(exc)
            self.close()
            return

        if became_ready:
            self.tls_ready = True
            self.establish(engine.selected_alpn())
            if self.transport is None or self.transport.is_closing():
                return

        if plaintext and self.connection is not None:
            self.connection.feed(plaintext)

        if engine.closed and self.transport is not None and not self.transport.is_closing():
            self.close()

    def connection_lost(self, exc: BaseException | None):
        self.closed = True
        self.transport = None

        raw = self.raw_transport
        self.raw_transport = None
        if raw is not None and self.handler is not None and not self.is_client:
            self.handler.active_transports.discard(raw)

        if self.connection is not None:
            self.connection.lost(exc)
            self.connection = None

        self.fail_ready(exc or ConnectionError("connection closed"))

    def set_ready(self):
        if self.ready is not None and not self.ready.done():
            self.ready.set_result(None)

    def fail_ready(self, exc: BaseException):
        if self.ready is not None and not self.ready.done():
            self.ready.set_exception(exc)

    def is_open(self) -> bool:
        return self.transport is not None and not self.closed

    def close(self):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

class WSClientProtocol(asyncio.Protocol):
    def __init__(self, loop: asyncio.AbstractEventLoop, max_message_size: int, tls_context: TLSContext | None = None, server_name: str | None = None):
        self.transport: asyncio.Transport | TLSTransport | None = None
        self.raw_transport: asyncio.Transport | None = None
        self.tls_context = tls_context
        self.server_name = server_name
        self.tls_engine: TLS | None = None
        self.tls_ready = False
        self.ready: asyncio.Future = loop.create_future()
        self.buffer = bytearray()
        self.handshake: asyncio.Future = loop.create_future()
        self.ws: WebSocket | None = None
        self.max_message_size = max_message_size

    def connection_made(self, transport: asyncio.BaseTransport):
        self.raw_transport = transport

        if self.tls_context is not None:
            self.tls_engine = self.tls_context.connection(self.server_name)
            self.transport = TLSTransport(transport, self.tls_engine)
            try:
                tls_start(self.tls_engine, transport)
            except Exception as exc:
                if not self.ready.done():
                    self.ready.set_exception(exc)
                transport.close()
            return

        self.transport = transport
        if not self.ready.done():
            self.ready.set_result(None)

    def data_received(self, data: bytes):
        if self.tls_engine is None:
            self.feed_decrypted(data)
            return

        engine = self.tls_engine
        try:
            became_ready, plaintext = tls_feed(engine, self.raw_transport, data)
        except Exception as exc:
            if not self.ready.done():
                self.ready.set_exception(exc)
            elif not self.handshake.done():
                self.handshake.set_exception(exc)
            if self.transport is not None:
                self.transport.close()
            return

        if became_ready and not self.ready.done():
            self.tls_ready = True
            self.ready.set_result(None)

        if plaintext:
            self.feed_decrypted(plaintext)

        if engine.closed and self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def feed_decrypted(self, data: bytes):
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
        except WebSocketProtocolError:
            self.ws.close_transport(1002)
            return
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
            except WebSocketProtocolError:
                ws.close_transport(1002)
                return
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
