from __future__ import annotations

import asyncio
from typing import Literal
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from importlib.metadata import version

from ..http import H1
from ..tls import TLSContext, TLSClientConfig
from ..models import Request, Response, Headers
from ..process import process_response, wrap_streaming_response
from ..websocket import WebSocket, generate_key, check_accept
from ..handler.tcp import TCPProtocol, WSClientProtocol
from ..http.h1 import H1Connection, H1Protocol
from ..http.h2 import H2Connection
from ..http.h3 import H3Connection, connect_quic

@dataclass
class Config:
    user_agent: str = f"Kaede/{version('nercone-kaede')} (+https://github.com/nercone-aki/kaede/)"

    protocols: list[Literal["http/1.1", "h2", "h3"]] = field(default_factory=lambda: ["h3", "h2", "http/1.1"])

    tls: TLSClientConfig = field(default_factory=lambda: TLSClientConfig())

    connect_timeout: float = 30
    read_timeout: float = 60

    max_body_size: int = 16 * 1024 * 1024
    max_concurrent_streams: int = 100
    max_websocket_message_size: int = 4 * 1024 * 1024

    max_connections_per_host: int = 10

    decompress: bool = True

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

class ClientHandler:
    def __init__(self, config: Config):
        self.config = config

        self.shared: dict[tuple, object] = {}
        self.idle: dict[tuple, list[H1Connection]] = {}
        self.locks: dict[tuple, asyncio.Lock] = {}
        self.origin_kind: dict[tuple, str] = {}
        self.connections: set = set()
        self.tasks: set[asyncio.Task] = set()

        self._tls_client_context: TLSContext | None = None

    def create_task(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def tls_client_context(self) -> TLSContext:
        if self._tls_client_context is None:
            alpn = tuple(p for p in self.config.protocols if p != "h3")
            self._tls_client_context = TLSContext.for_client(self.config.tls, alpn=alpn)
        return self._tls_client_context

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
                    conn = await self.connect_tcp(key, host, port, authority, self.tls_client_context())
                self.origin_kind[key] = kind
                return conn
            except Exception as exc:
                last_error = exc

        raise last_error or ConnectionError(f"failed to connect to {host}:{port}")

    def make_connection(self, protocol: TCPProtocol, alpn: str | None, key: tuple, authority: str):
        if alpn == "h2":
            return H2Connection(protocol, is_client=True, key=key, authority=authority)
        return H1Connection(protocol, is_client=True, key=key, authority=authority)

    async def connect_tcp(self, key: tuple, host: str, port: int, authority: str, tls_context: TLSContext | None):
        loop = asyncio.get_running_loop()

        if tls_context is None:
            protocol = H1Protocol(self, is_client=True, key=key, authority=authority)
        else:
            protocol = TCPProtocol(is_client=True, factory=lambda proto, alpn: self.make_connection(proto, alpn, key, authority), tls_context=tls_context, server_name=host, handler=self)

        await asyncio.wait_for(loop.create_connection(lambda: protocol, host, port), timeout=self.config.connect_timeout)
        await protocol.ready
        return protocol.connection

    async def connect_quic(self, host: str, port: int, authority: str) -> H3Connection:
        return await connect_quic(
            self,
            host,
            port,
            authority,
            server_name=host,
            tls_config=self.config.tls,
            connect_timeout=self.config.connect_timeout,
        )

    def release_h1(self, conn: H1Connection):
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
                    continue

                conn = await self.connect_tcp(key, host, port, authority, self.tls_client_context())
                self.connections.add(conn)

                if conn.mode == "h2":
                    return await conn.websocket(request, subprotocols)

                conn.close()
                self.discard(conn)
                return await self.websocket_h1(host, port, authority, request, subprotocols, self.tls_client_context())

            except Exception as exc:
                last_error = exc

        raise last_error or ConnectionError(f"failed to establish websocket to {host}:{port}")

    async def websocket_h1(self, host: str, port: int, authority: str, request: Request, subprotocols: list[str] | None, tls_context: TLSContext | None) -> WebSocket:
        loop = asyncio.get_running_loop()
        protocol = WSClientProtocol(loop, self.config.max_websocket_message_size, tls_context=tls_context, server_name=host if tls_context else None)

        await asyncio.wait_for(
            loop.create_connection(lambda: protocol, host, port),
            timeout=self.config.connect_timeout,
        )

        await asyncio.wait_for(protocol.ready, self.config.connect_timeout)

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
            if isinstance(conn, H3Connection):
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
    def __init__(self, handler: ClientHandler, method: str, url: str, headers: dict[str, str] | None, body: bytes | None):
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
        self.handler = ClientHandler(self.config)

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
