from __future__ import annotations

import os
import signal
import socket
import uvloop
import asyncio
from typing import Literal
from dataclasses import dataclass, field

from ..tls import TLSContext, TLSServerConfig
from ..models import Listener, Callback
from ..websocket import WebSocket
from ..handler.tcp import TCPProtocol
from ..http.h1 import H1Connection, H1Protocol
from ..http.h2 import H2Connection
from ..http.h3 import H3Protocol

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

class ServerHandler:
    def __init__(self, listener: Listener, callback: Callback, config: Config):
        self.listener = listener
        self.callback = callback
        self.config = config
        self.shutdown = False

        self.tcp_server: asyncio.base_events.Server | None = None
        self.quic_transport: asyncio.DatagramTransport | None = None

        self._tls_server_context: TLSContext | None = None

        self.active_tasks: set[asyncio.Task] = set()
        self.active_transports: set[asyncio.Transport] = set()
        self.active_websockets: set[WebSocket] = set()

    def create_task(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.active_tasks.add(task)
        task.add_done_callback(self.active_tasks.discard)
        return task

    def tls_server_context(self) -> TLSContext:
        if self._tls_server_context is None:
            alpn = tuple(p for p in self.config.protocols if p != "h3")
            self._tls_server_context = TLSContext.for_server(self.config.tls, alpn=alpn)
        return self._tls_server_context

    def make_connection(self, protocol: TCPProtocol, alpn: str | None):
        if alpn == "h2" and "h2" in self.config.protocols:
            return H2Connection(protocol, is_client=False)
        if "http/1.1" in self.config.protocols:
            return H1Connection(protocol, is_client=False)
        return None

    async def start(self):
        loop = asyncio.get_running_loop()
        kind = self.listener.kind

        if kind in ("http", "unix"):
            self.tcp_server = await loop.create_server(lambda: H1Protocol(self), sock=self.listener.sock)

        elif kind == "https":
            tls_context = self.tls_server_context()
            self.tcp_server = await loop.create_server(lambda: TCPProtocol(is_client=False, factory=self.make_connection, tls_context=tls_context, handler=self), sock=self.listener.sock)

        elif kind == "quic":
            transport, _ = await loop.create_datagram_endpoint(lambda: H3Protocol(self), sock=self.listener.sock)
            self.quic_transport = transport

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

        if self.quic_transport is not None:
            self.quic_transport.close()
            self.quic_transport = None

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
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

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
        handlers = [ServerHandler(listener, self.callback, self.config) for listener in (listeners if listeners is not None else self.listeners())]

        for handler in handlers:
            await handler.start()

        loop = asyncio.get_running_loop()
        stop = loop.create_future()

        def handle_signal():
            if not stop.done():
                stop.set_result(None)

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, handle_signal)

        try:
            await stop
        finally:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: None)

            await asyncio.gather(*[handler.drain(self.config.shutdown_timeout) for handler in handlers], return_exceptions=True)

            for handler in handlers:
                await handler.stop()

            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)
