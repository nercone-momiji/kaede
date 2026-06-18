from __future__ import annotations

import os
import gzip
import zlib
import socket
import asyncio
import rjsmin
import rcssmin
import ipaddress
import zstandard
import brotlicffi
import minify_html
from scour import scour
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Literal, Awaitable
from dataclasses import dataclass, field

from .tls import TLSInfo
from .websocket import WebSocket

if TYPE_CHECKING:
    from .http.h2 import H2Info
    from .http.h3 import H3Info

@dataclass
class Request:
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytes | None = None
    content_type: str | None = None

    client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] = field(default_factory=lambda: (ipaddress.IPv4Address("0.0.0.0"), 0))
    scheme: Literal["http", "https"] = "http"
    secure: bool = False

    compression: bool = True
    minification: bool = False

    compressed: bytes | AsyncIterator[bytes] | None = None
    minified: bytes | AsyncIterator[bytes] | None = None

    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1"

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

    async def compress(self, encoding: str = "zstd"):
        if not (self.body is not None and self.compression):
            return

        if "Content-Encoding" in self.headers:
            return

        content_type = (self.content_type or self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()

        if content_type.startswith(("image/", "video/", "audio/")) and content_type != "image/svg+xml":
            return

        if content_type in ("application/zip", "application/gzip", "application/x-gzip", "application/zstd", "application/x-zstd", "application/x-bzip2", "application/x-xz", "application/x-7z-compressed", "application/x-rar-compressed", "application/pdf", "application/ogg", "font/woff", "font/woff2"):
            return

        if encoding == "zstd":
            self.body = zstandard.ZstdCompressor(level=3).compress(self.body)
        elif encoding == "br":
            self.body = brotlicffi.compress(self.body, quality=4)
        elif encoding == "gzip":
            self.body = gzip.compress(self.body, compresslevel=6)
        elif encoding == "deflate":
            self.body = zlib.compress(self.body, level=6)

        self.headers.set("Content-Encoding", encoding)

    def decompress(self, encoding: str | None = None, max_size: int | None = None):
        if not self.compression or self.body is not None or self.compressed is None:
            return

        encoding = encoding.strip().lower() if encoding is not None else self.headers.get("Content-Encoding", "").strip().lower()

        if encoding == "zstd":
            decompressor = zstandard.ZstdDecompressor()

            if max_size is not None:
                try:
                    result = decompressor.decompress(self.compressed, max_output_size=max_size + 1)
                except Exception as exc:
                    raise ValueError("zstd decompression failed") from exc

                if len(result) > max_size:
                    raise ValueError("decompressed body exceeds limit")

                self.body = result

            else:
                self.body = decompressor.decompressobj().decompress(self.compressed)

        elif encoding == "br":
            result = brotlicffi.decompress(self.compressed)

            if max_size is not None and len(result) > max_size:
                raise ValueError("decompressed body exceeds limit")

            self.body = result

        elif encoding in ("gzip", "x-gzip"):
            if max_size is not None:
                decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
                result = decompressor.decompress(self.compressed, max_size)

                if decompressor.unconsumed_tail:
                    raise ValueError("decompressed body exceeds limit")

                self.body = result

            else:
                self.body = gzip.decompress(self.compressed)

        elif encoding == "deflate":
            if max_size is not None:
                try:
                    decompressor = zlib.decompressobj()
                    result = decompressor.decompress(self.compressed, max_size)

                    if decompressor.unconsumed_tail:
                        raise ValueError("decompressed body exceeds limit")

                    self.body = result

                except zlib.error:
                    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                    result = decompressor.decompress(self.compressed, max_size)

                    if decompressor.unconsumed_tail:
                        raise ValueError("decompressed body exceeds limit")

                    self.body = result

            else:
                try:
                    self.body = zlib.decompress(self.compressed)
                except zlib.error:
                    self.body = zlib.decompress(self.compressed, -zlib.MAX_WBITS)

@dataclass
class Response:
    body: bytes | AsyncIterator[bytes] | os.PathLike | None = None
    status_code: int = 200
    headers: Headers = field(default_factory=lambda: Headers({}))
    content_type: str | None = None

    compression: bool = True
    minification: bool = False

    compressed: bytes | AsyncIterator[bytes] | None = None
    minified: bytes | AsyncIterator[bytes] | None = None

    protocol: Literal["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1"

    file_range: tuple[int, int] | None = field(default=None)

    @property
    def has_real_body(self) -> bool:
        return self.body is not None and isinstance(self.body, bytes)

    @property
    def is_streaming(self) -> bool:
        return hasattr(self.body, "__aiter__")

    async def compress(self, accepted_encodings: dict[str, float], max_compressible_file_size: int = 16 * 1024 * 1024):
        if not (self.body is not None and self.compression and accepted_encodings):
            return

        if "Content-Encoding" in self.headers:
            return

        content_type = (self.content_type or self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()

        if content_type.startswith(("image/", "video/", "audio/")) and content_type != "image/svg+xml":
            return

        if content_type in ("application/zip", "application/gzip", "application/x-gzip", "application/zstd", "application/x-zstd", "application/x-bzip2", "application/x-xz", "application/x-7z-compressed", "application/x-rar-compressed", "application/pdf", "application/ogg", "font/woff", "font/woff2"):
            return

        star_q = accepted_encodings.get("*")
        scored: list[tuple[float, int, str]] = []

        for encoding, priority in (("zstd", 0), ("br", 1), ("gzip", 2), ("deflate", 3)):
            q = accepted_encodings.get(encoding) or star_q

            if q is None or q <= 0:
                continue

            scored.append((-q, priority, encoding))

        scored.sort()

        for _, _, encoding in scored:
            if self.is_streaming:
                body = self.body

                if encoding == "zstd":
                    async def compress_stream_zstd(src=body):
                        compressor = zstandard.ZstdCompressor(level=3).compressobj()

                        async for chunk in src:
                            out = compressor.compress(chunk)
                            if out:
                                yield out

                        out = compressor.flush(zstandard.COMPRESSOBJ_FLUSH_FINISH)
                        if out:
                            yield out

                    self.body = compress_stream_zstd()

                elif encoding == "br":
                    async def compress_stream_brotli(src=body):
                        compressor = brotlicffi.Compressor(quality=4)

                        async for chunk in src:
                            out = compressor.process(chunk)

                            if out:
                                yield out

                        out = compressor.finish()
                        if out:
                            yield out

                    self.body = compress_stream_brotli()

                elif encoding == "gzip":
                    async def compress_stream_gzip(src=body):
                        compressor = zlib.compressobj(level=6, wbits=31)

                        async for chunk in src:
                            out = compressor.compress(chunk)

                            if out:
                                yield out

                        out = compressor.flush(zlib.Z_FINISH)
                        if out:
                            yield out

                    self.body = compress_stream_gzip()

                elif encoding == "deflate":
                    async def compress_stream_deflate(src=body):
                        compressor = zlib.compressobj(level=6)

                        async for chunk in src:
                            out = compressor.compress(chunk)
                            if out:
                                yield out

                        out = compressor.flush(zlib.Z_FINISH)
                        if out:
                            yield out

                    self.body = compress_stream_deflate()

                else:
                    continue

                self.headers.set("Content-Encoding", encoding)
                self.headers.append_vary("Accept-Encoding")

                return

            if self.has_real_body:
                try:
                    if encoding == "zstd":
                        self.body = zstandard.ZstdCompressor(level=3).compress(self.body)
                    elif encoding == "br":
                        self.body = brotlicffi.compress(self.body, quality=4)
                    elif encoding == "gzip":
                        self.body = gzip.compress(self.body, compresslevel=6)
                    elif encoding == "deflate":
                        self.body = zlib.compress(self.body, level=6)
                    else:
                        continue
                except Exception:
                    continue

                self.headers.set("Content-Encoding", encoding)
                self.headers.append_vary("Accept-Encoding")

                return

            loop = asyncio.get_running_loop()

            try:
                path_str = os.fspath(self.body)

                if await loop.run_in_executor(None, os.path.getsize, path_str) > max_compressible_file_size:
                    return

                def read_file():
                    with open(path_str, "rb") as f:
                        return f.read()

                data = await loop.run_in_executor(None, read_file)

                if encoding == "zstd":
                    compressed = zstandard.ZstdCompressor(level=3).compress(data)
                elif encoding == "br":
                    compressed = brotlicffi.compress(data, quality=4)
                elif encoding == "gzip":
                    compressed = gzip.compress(data, compresslevel=6)
                elif encoding == "deflate":
                    compressed = zlib.compress(data, level=6)
                else:
                    continue

            except Exception:
                continue

            self.body = compressed
            self.headers.set("Content-Encoding", encoding)
            self.headers.append_vary("Accept-Encoding")

            return

    def decompress(self, encoding: str | None = None, max_size: int | None = None):
        if not self.compression or self.body is not None or self.compressed is None:
            return

        encoding = encoding.strip().lower() if encoding is not None else self.headers.get("Content-Encoding", "").strip().lower()

        if hasattr(self.compressed, "__aiter__"):
            compressed = self.compressed

            if encoding == "zstd":
                async def decompress_stream_zstd(src=compressed, _max=max_size):
                    decompressor = zstandard.ZstdDecompressor().decompressobj()
                    total = 0

                    async for chunk in src:
                        out = decompressor.decompress(chunk)
                        if out:
                            total += len(out)
                            if _max is not None and total > _max:
                                raise ValueError("decompressed streaming body exceeds limit")
                            yield out

                self.body = decompress_stream_zstd()

            elif encoding == "br":
                async def decompress_stream_brotli(src=compressed, _max=max_size):
                    decompressor = brotlicffi.Decompressor()
                    total = 0

                    async for chunk in src:
                        out = decompressor.process(chunk)
                        if out:
                            total += len(out)
                            if _max is not None and total > _max:
                                raise ValueError("decompressed streaming body exceeds limit")
                            yield out

                self.body = decompress_stream_brotli()

            elif encoding in ("gzip", "x-gzip"):
                async def decompress_stream_gzip(src=compressed, _max=max_size):
                    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    total = 0

                    async for chunk in src:
                        out = decompressor.decompress(chunk)
                        if out:
                            total += len(out)
                            if _max is not None and total > _max:
                                raise ValueError("decompressed streaming body exceeds limit")
                            yield out

                    out = decompressor.flush()
                    if out:
                        yield out

                self.body = decompress_stream_gzip()

            elif encoding == "deflate":
                async def decompress_stream_deflate(src=compressed, _max=max_size):
                    decompressor = zlib.decompressobj(zlib.MAX_WBITS)
                    total = 0

                    async for chunk in src:
                        out = decompressor.decompress(chunk)
                        if out:
                            total += len(out)
                            if _max is not None and total > _max:
                                raise ValueError("decompressed streaming body exceeds limit")
                            yield out

                    out = decompressor.flush()
                    if out:
                        yield out

                self.body = decompress_stream_deflate()

        else:
            if encoding == "zstd":
                decompressor = zstandard.ZstdDecompressor()

                if max_size is not None:
                    try:
                        result = decompressor.decompress(self.compressed, max_output_size=max_size + 1)
                    except Exception as exc:
                        raise ValueError("zstd decompression failed") from exc

                    if len(result) > max_size:
                        raise ValueError("decompressed body exceeds limit")

                    self.body = result

                else:
                    self.body = decompressor.decompressobj().decompress(self.compressed)

            elif encoding == "br":
                result = brotlicffi.decompress(self.compressed)

                if max_size is not None and len(result) > max_size:
                    raise ValueError("decompressed body exceeds limit")

                self.body = result

            elif encoding in ("gzip", "x-gzip"):
                if max_size is not None:
                    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
                    result = decompressor.decompress(self.compressed, max_size)

                    if decompressor.unconsumed_tail:
                        raise ValueError("decompressed body exceeds limit")

                    self.body = result

                else:
                    self.body = gzip.decompress(self.compressed)

            elif encoding == "deflate":
                if max_size is not None:
                    try:
                        decompressor = zlib.decompressobj()
                        result = decompressor.decompress(self.compressed, max_size)

                        if decompressor.unconsumed_tail:
                            raise ValueError("decompressed body exceeds limit")

                        self.body = result

                    except zlib.error:
                        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                        result = decompressor.decompress(self.compressed, max_size)

                        if decompressor.unconsumed_tail:
                            raise ValueError("decompressed body exceeds limit")

                        self.body = result

                else:
                    try:
                        self.body = zlib.decompress(self.compressed)
                    except zlib.error:
                        self.body = zlib.decompress(self.compressed, -zlib.MAX_WBITS)

    async def minify(self, *, html: bool = False, css: bool = False, js: bool = False, svg: bool = False, keep_html_comments: bool = False):
        if not (self.minification and self.has_real_body):
            return

        content_type = (self.content_type or self.headers.get("Content-Type") or "").strip().lower()

        try:
            if html and content_type.startswith("text/html"):
                self.body = minify_html.minify(self.body.decode("utf-8", errors="replace"), minify_js=True, minify_css=True, keep_comments=keep_html_comments, keep_html_and_head_opening_tags=True).encode("utf-8")
            elif css and content_type.startswith("text/css"):
                self.body = rcssmin.cssmin(self.body.decode("utf-8", errors="replace")).encode("utf-8")
            elif js and content_type.startswith(("text/javascript", "application/javascript")):
                self.body = rjsmin.jsmin(self.body.decode("utf-8", errors="replace")).encode("utf-8")
            elif svg and content_type.startswith("image/svg"):
                options = scour.generateDefaultOptions()
                options.newlines = False
                options.shorten_ids = True
                options.strip_comments = True
                self.body = scour.scourString(self.body.decode("utf-8", errors="replace"), options).encode("utf-8")
        except Exception:
            pass

@dataclass
class RawRequest:
    method: str = ""
    target: str = ""
    scheme: str = "https"
    authority: str = ""
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytearray = field(default_factory=bytearray)

@dataclass
class RawResponse:
    status_code: int = 0
    headers: Headers = field(default_factory=lambda: Headers({}))
    body: bytearray = field(default_factory=bytearray)

@dataclass
class Listener:
    sock: socket.socket
    kind: Literal["http", "https", "quic", "unix"]

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

    def __getitem__(self, key: str) -> str | list[str] | None:
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
