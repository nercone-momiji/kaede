from __future__ import annotations

import os
import socket
import ipaddress
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Literal, Awaitable
from dataclasses import dataclass, field

from .tls import TLSInfo
from .websocket import WebSocket

if TYPE_CHECKING:
    from .h2 import H2Info
    from .h3 import H3Info

@dataclass
class Listener:
    sock: socket.socket
    kind: Literal["http", "https", "quic", "unix"]

@dataclass
class Request:
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str

    client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] = field(default_factory=lambda: (ipaddress.IPv4Address("0.0.0.0"), 0))
    scheme: Literal["http", "https"] = "http"
    secure: bool = False

    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1"
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytes | None = None

    h2: H2Info | None = None
    h3: H3Info | None = None
    tls: TLSInfo | None = None

    @property
    def is_websocket_upgrade(self) -> bool:
        upgrade           = (self.headers.get("Upgrade") or "").lower().strip()
        connection        = (self.headers.get("Connection") or "").lower()
        websocket_key     = (self.headers.get("Sec-WebSocket-Key") or "").strip()
        websocket_version = (self.headers.get("Sec-WebSocket-Version") or "").strip()

        return upgrade == "websocket" and "upgrade" in connection and bool(websocket_key) and websocket_version == "13"

@dataclass
class Response:
    body: bytes | AsyncIterator[bytes] | os.PathLike | None = None
    status_code: int = 200
    headers: Headers = field(default_factory=lambda: Headers({}))
    content_type: str | None = None

    compression: bool = True
    minification: bool = False

    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1"

    file_range: tuple[int, int] | None = field(default=None)

    @property
    def has_real_body(self) -> bool:
        return self.body is not None and isinstance(self.body, bytes)

    @property
    def is_streaming(self) -> bool:
        return hasattr(self.body, "__aiter__")

@dataclass
class RequestStream:
    method: str = ""
    target: str = ""
    scheme: str = "https"
    authority: str = ""
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytearray = field(default_factory=bytearray)

@dataclass
class ResponseStream:
    status_code: int = 0
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytearray = field(default_factory=bytearray)

class Callback:
    def __init__(self):
        self.websocket_subprotocols: list[str] = []

    async def on_request(self, request: Request) -> Response | Awaitable[Response]:
        return Response("Hello, World! This is the Response from the default Kaede Callback.".encode(), content_type="text/plain")

    async def on_websocket(self, request: Request, ws: WebSocket):
        await ws.close(1008, "WebSocket not configured")

class Headers:
    def __init__(self, headers: dict[str, str]):
        self.headers: dict[str, list[str]] = {}
        for k, v in headers.items():
            self.append(k, v)

    def __getitem__(self, key: str) -> str | None:
        return self.get(key.lower())

    def __setitem__(self, key: str, value: str):
        self.set(key.lower(), value)

    def __contains__(self, item: str):
        return item.lower() in self.headers

    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for k, values in self.headers.items() for v in values]

    def get(self, key: str, default=None) -> str | list[str] | None:
        values = self.headers.get(key.lower())
        if not values:
            return default
        if key.lower() == "set-cookie":
            return values
        return ", ".join(values)

    def set(self, key: str, value: str, override: bool = True):
        if override or key.lower() not in self.headers:
            self.headers[key.lower()] = [value]

    def append(self, key: str, value: str):
        if key.lower() in self.headers:
            self.headers[key.lower()].append(value)
        else:
            self.headers[key.lower()] = [value]

    def remove(self, key: str):
        self.headers.pop(key.lower(), None)

    def append_vary(self, header: str):
        vary = [v.strip() for v in self.get("Vary", "").split(",") if v.strip()]

        if not any(v.lower() == header.lower() for v in vary):
            vary.append(header)

        self.set("Vary", ", ".join(vary))
