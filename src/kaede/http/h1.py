from __future__ import annotations

import os
import asyncio
import ipaddress
from http import HTTPStatus
from typing import Literal

from ..models import Request, Response, Headers
from ..tls import TLSInfo
from ..process import process_request
from ..websocket import WebSocket, WebSocketProtocolError, compute_accept, parse_frames
from ..handler.common import StreamState, consume_response, negotiate_websocket, MAX_RESPONSE_HEADER_SIZE
from ..handler.tcp import TCPProtocol

class H1:
    @staticmethod
    def parse_request(data: bytes, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "http", secure: bool = False, tls: TLSInfo | None = None, max_body_size: int | None = None) -> Request:
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            raise ValueError("incomplete HTTP/1.1 request: missing header terminator")

        lines = head.split(b"\r\n")
        if not lines or not lines[0]:
            raise ValueError("empty HTTP/1.1 request line")

        try:
            method_b, target_b, version_b = lines[0].split(b" ", 2)
        except ValueError:
            raise ValueError("malformed HTTP/1.1 request line")

        if version_b != b"HTTP/1.1":
            raise ValueError(f"unsupported HTTP version: {version_b!r}")

        headers = Headers({})
        for line in lines[1:]:
            if not line:
                continue
            name_b, sep_b, value_b = line.partition(b":")
            if not sep_b:
                raise ValueError(f"malformed HTTP/1.1 header: {line!r}")
            headers.append(name_b.decode("latin-1").strip(), value_b.decode("latin-1").strip())

        body: bytes | None = None
        transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
        content_length = headers.get("Content-Length")

        if transfer_encoding:
            te_tokens = [t.strip() for t in transfer_encoding.split(",") if t.strip()]
            if te_tokens[-1:] != ["chunked"] or te_tokens.count("chunked") != 1:
                raise ValueError(f"invalid Transfer-Encoding: {transfer_encoding!r}")
            is_chunked = True
        else:
            is_chunked = False

        if is_chunked and content_length is not None:
            raise ValueError("both Transfer-Encoding and Content-Length present")

        if is_chunked:
            body = H1.decode_chunked(rest, max_body_size=max_body_size)

        elif content_length is not None:
            if isinstance(content_length, list) or not (content_length.isascii() and content_length.isdigit()):
                raise ValueError(f"invalid Content-Length: {content_length!r}")
            n = int(content_length)
            if max_body_size is not None and n > max_body_size:
                raise ValueError(f"Content-Length exceeds max_body_size: {n}")
            body = rest[:n] if n > 0 else None

        return Request(client=client, scheme=scheme, secure=secure, protocol="HTTP/1.1", method=method_b.decode("ascii"), target=target_b.decode("latin-1"), headers=headers, body=body, h2=None, h3=None, tls=tls)

    @staticmethod
    def build_response(response: Response) -> bytes | tuple[bytes, os.PathLike | None]:
        if response.has_real_body:
            return H1.build_response_head(response) + response.body
        else:
            return H1.build_response_head(response), response.body

    @staticmethod
    def build_response_head(response: Response) -> bytes:
        try:
            phrase = HTTPStatus(response.status_code).phrase
        except ValueError:
            phrase = ""

        built = f"HTTP/1.1 {response.status_code}" + (f" {phrase}" if phrase else "") + "\r\n"

        for key, value in response.headers.items():
            if any(c in key for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue

            built += f"{key}: {value}\r\n"
    
        built += "\r\n"

        return built.encode("latin-1")

    @staticmethod
    def build_request(request: Request) -> bytes:
        if request.body:
            return H1.build_request_head(request) + request.body
        return H1.build_request_head(request)

    @staticmethod
    def build_request_head(request: Request) -> bytes:
        built = f"{request.method} {request.target} HTTP/1.1\r\n"
        for key, value in request.headers.items():
            if any(c in key for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            built += f"{key}: {value}\r\n"
        built += "\r\n"
        return built.encode("latin-1")

    @staticmethod
    def response_has_no_body(status_code: int, method: str) -> bool:
        return method.upper() == "HEAD" or 100 <= status_code < 200 or status_code in (204, 304)

    @staticmethod
    def parse_response_head(head: bytes) -> tuple[int, str, Headers]:
        lines = head.split(b"\r\n")
        if not lines or not lines[0]:
            raise ValueError("empty HTTP/1.1 status line")

        parts = lines[0].split(b" ", 2)
        if len(parts) < 2:
            raise ValueError("malformed HTTP/1.1 status line")

        version_b, status_b = parts[0], parts[1]
        phrase = parts[2].decode("latin-1") if len(parts) > 2 else ""

        if version_b != b"HTTP/1.1":
            raise ValueError(f"unsupported HTTP version: {version_b!r}")

        if not (status_b.isascii() and status_b.isdigit()):
            raise ValueError(f"invalid HTTP status code: {status_b!r}")

        status = int(status_b)

        headers = Headers({})
        for line in lines[1:]:
            if not line:
                continue
            name_b, sep_b, value_b = line.partition(b":")
            if not sep_b:
                raise ValueError(f"malformed HTTP/1.1 header: {line!r}")
            headers.append(name_b.decode("latin-1").strip(), value_b.decode("latin-1").strip())

        return status, phrase, headers

    @staticmethod
    def parse_response(data: bytes, *, method: str = "GET", max_body_size: int | None = None) -> Response:
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            raise ValueError("incomplete HTTP/1.1 response: missing header terminator")

        status, _, headers = H1.parse_response_head(head)

        body: bytes | None = None

        if not H1.response_has_no_body(status, method):
            transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
            content_length = headers.get("Content-Length")

            if transfer_encoding:
                te_tokens = [t.strip() for t in transfer_encoding.split(",") if t.strip()]

                if te_tokens[-1:] != ["chunked"] or te_tokens.count("chunked") != 1:
                    raise ValueError(f"invalid Transfer-Encoding: {transfer_encoding!r}")

                body = H1.decode_chunked(rest, max_body_size=max_body_size)

            elif content_length is not None:
                if isinstance(content_length, list) or not (content_length.isascii() and content_length.isdigit()):
                    raise ValueError(f"invalid Content-Length: {content_length!r}")

                n = int(content_length)

                if max_body_size is not None and n > max_body_size:
                    raise ValueError(f"Content-Length exceeds max_body_size: {n}")

                body = rest[:n] if n > 0 else None

            else:
                body = bytes(rest) if rest else None

        return Response(body=body, status_code=status, headers=headers, protocol="HTTP/1.1")

    @staticmethod
    def decode_chunked(data: bytes, max_body_size: int | None = None) -> bytes | None:
        result = H1.scan_chunked(data, max_body_size=max_body_size)
        if result is None:
            raise ValueError("malformed chunked body: incomplete")
        body, _ = result
        return body

    @staticmethod
    def scan_chunked(data: bytes, max_body_size: int | None = None) -> tuple[bytes | None, int] | None:
        body = bytearray()
        i = 0

        while True:
            end = data.find(b"\r\n", i)
            if end == -1:
                return None

            size_line = data[i:end].split(b";", 1)[0].strip()

            try:
                size = int(size_line, 16)
            except ValueError:
                raise ValueError(f"invalid chunk size: {size_line!r}")

            if size < 0:
                raise ValueError(f"negative chunk size: {size}")

            if max_body_size is not None and len(body) + size > max_body_size:
                raise ValueError("chunked body exceeds max_body_size")

            i = end + 2
            if size == 0:
                while True:
                    line_end = data.find(b"\r\n", i)
                    if line_end == -1:
                        return None

                    is_empty = (line_end == i)
                    i = line_end + 2

                    if is_empty:
                        break

                return bytes(body) if body else None, i

            if len(data) < i + size + 2:
                return None

            if data[i + size:i + size + 2] != b"\r\n":
                raise ValueError("malformed chunk: missing CRLF terminator")

            body.extend(data[i:i + size])
            i += size + 2

class H1Connection:
    """Manages a single HTTP/1.1 connection (server or client side).

    Holds the per-connection state machine and drives requests/responses over
    the transport owned by an :class:`H1Protocol`. Stateless protocol logic is
    delegated to :class:`H1`.
    """

    def __init__(self, protocol, is_client: bool = False, *, key: tuple | None = None, authority: str | None = None):
        self.protocol = protocol
        self.handler = protocol.handler
        self.is_client = is_client

        self.key = key
        self.authority = authority
        self.mode = "h1"
        self.multiplexed = False

        # server state
        self.buffer = bytearray()
        self.websocket: WebSocket | None = None
        self.websocket_buffer: bytearray = bytearray()
        self.websocket_pending: bool = False
        self.continue_sent: bool = False
        self.reading_paused: bool = False
        self.keep_alive: bool = True
        self.keep_alive_handle: asyncio.TimerHandle | None = None
        self.request_queue: asyncio.Queue[tuple[Request, bool] | None] = asyncio.Queue()
        self.request_consumer: asyncio.Task | None = None

        # client state
        self.current: StreamState | None = None
        self.method = "GET"
        self.state = "idle"
        self.remaining = 0
        self.chunk_remaining = 0
        self.headers: Headers | None = None
        self.reusable = False

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

    def start(self):
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

    # --- server: keepalive ---

    def reset_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        if self.transport is not None and self.keep_alive and self.websocket is None:
            self.keep_alive_handle = asyncio.get_running_loop().call_later(self.config.keepalive_timeout, self.on_keepalive_timeout)

    def cancel_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

    def on_keepalive_timeout(self):
        self.keep_alive_handle = None
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    # --- server: receive ---

    def feed_server(self, data: bytes):
        if self.transport is None:
            return

        self.reset_keepalive()

        if self.websocket is not None:
            self.websocket_buffer.extend(data)

            try:
                frames = parse_frames(self.websocket_buffer, self.config.max_websocket_message_size)
            except WebSocketProtocolError:
                self.websocket.close_transport(1002)
                return
            except ValueError:
                self.websocket.close_transport(1009)
                return

            for frame in frames:
                self.websocket.feed_frame(frame)

            return

        if self.websocket_pending:
            self.buffer.extend(data)
            return

        self.buffer.extend(data)

        while True:
            head_end = self.buffer.find(b"\r\n\r\n")

            if head_end == -1:
                if len(self.buffer) > self.config.max_header_size:
                    self.send_error(431, "Request Header Fields Too Large")
                    self.transport.close()
                return

            if head_end > self.config.max_header_size:
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
                    scan = H1.scan_chunked(bytes(self.buffer[body_start:]), max_body_size=self.config.max_body_size)
                except ValueError:
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                if scan is None:
                    if len(self.buffer) - body_start > self.config.max_body_size:
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
                if expected > self.config.max_body_size:
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
                request = H1.parse_request(bytes(self.buffer[:consumed]), client=self.client, scheme="https" if self.secure else "http", secure=self.secure, tls=self.tls, max_body_size=self.config.max_body_size)
            except (ValueError, UnicodeDecodeError):
                self.transport.close()
                return

            del self.buffer[:consumed]
            self.continue_sent = False

            keep_alive = not "close" in (request.headers.get("Connection") or "").lower()

            if self.request_consumer is None:
                self.request_consumer = self.handler.create_task(self.consume_requests())

            self.request_queue.put_nowait((request, keep_alive))

            if request.is_websocket_upgrade:
                self.websocket_pending = True
                return

            if not keep_alive:
                return

            if not self.reading_paused and self.request_queue.qsize() >= self.config.max_pipeline_buffer_len:
                self.reading_paused = True
                self.transport.pause_reading()
                return

    def send_continue(self, expect_continue: bool):
        if expect_continue and not self.continue_sent and self.transport is not None and not self.transport.is_closing():
            self.continue_sent = True
            self.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    def send_error(self, status: int, phrase: str):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.write(f"HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("latin-1"))

    # --- server: response ---

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

            await self.websocket_upgrade(request, request.headers.get("Sec-WebSocket-Key", "").strip())
            return

        response = await process_request(request, callback=self.handler.callback, config=self.config)

        if self.handler.shutdown:
            response.headers.set("Connection", "close")
            self.keep_alive = False

        if "h3" in self.config.protocols and self.config.bind_quic:
            _, _, h3_port = self.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        if response.is_streaming:
            await self.stream(response)
            return

        result = H1.build_response(response)

        if isinstance(result, tuple):
            head, alt_body = result
            self.transport.write(head)

            if alt_body is not None:
                await self.send_file(alt_body, response.file_range)

        else:
            self.transport.write(result)

        if not self.keep_alive:
            self.transport.close()

    async def stream(self, response: Response):
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

    async def send_file(self, path: os.PathLike, file_range: tuple[int, int] | None = None):
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

    async def consume_requests(self):
        while True:
            item = await self.request_queue.get()
            if item is None or self.transport is None:
                break

            self.cancel_keepalive()

            request, keep_alive = item
            self.keep_alive = keep_alive

            await self.respond(request)

            if self.websocket is not None:
                break
            if not self.keep_alive or self.transport is None:
                break

            if self.reading_paused and self.request_queue.qsize() < self.config.max_pipeline_buffer_len // 2 and not self.transport.is_closing():
                self.reading_paused = False
                self.transport.resume_reading()

            self.reset_keepalive()

    async def websocket_upgrade(self, request: Request, ws_key: str):
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
        ws = WebSocket(self.transport, subprotocol=subprotocol, deflate=deflate, max_message_size=self.config.max_websocket_message_size)
        self.websocket = ws

        self.websocket_buffer = self.buffer
        self.buffer = bytearray()
        self.websocket_pending = False

        self.handler.create_task(self.run_websocket(request, ws))

        if self.websocket_buffer:
            try:
                frames = parse_frames(self.websocket_buffer, self.config.max_websocket_message_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                return
            except ValueError:
                ws.close_transport(1009)
                return
            for frame in frames:
                ws.feed_frame(frame)

    def server_lost(self, exc: BaseException | None):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        if self.websocket is not None and not self.websocket.closed:
            self.websocket.queue.put_nowait(None)

        self.request_queue.put_nowait(None)
        self.buffer.clear()

    # --- client: receive ---

    def feed_client(self, data: bytes):
        self.buffer.extend(data)

        while self.current is not None:
            if self.state == "head":
                idx = self.buffer.find(b"\r\n\r\n")
                if idx == -1:
                    if len(self.buffer) > MAX_RESPONSE_HEADER_SIZE:
                        self.fail_request(ValueError("response header too large"))
                    return

                head = bytes(self.buffer[:idx])
                del self.buffer[:idx + 4]

                try:
                    status, _, headers = H1.parse_response_head(head)
                except ValueError as exc:
                    self.fail_request(exc)
                    return

                if 100 <= status < 200 and status != 101:
                    continue

                self.headers = headers

                if H1.response_has_no_body(status, self.method):
                    self.current.set_headers(status, headers)
                    self.finish_request()
                    return

                transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
                content_length = headers.get("Content-Length")

                if transfer_encoding:
                    te_tokens = [t.strip() for t in transfer_encoding.split(",") if t.strip()]

                    if te_tokens[-1:] != ["chunked"]:
                        self.fail_request(ValueError("invalid Transfer-Encoding"))
                        return

                    self.current.set_headers(status, headers)
                    self.state = "chunk-size"

                elif content_length is not None:
                    if isinstance(content_length, list) or not (content_length.isascii() and content_length.isdigit()):
                        self.fail_request(ValueError("invalid Content-Length"))
                        return

                    self.remaining = int(content_length)
                    self.current.set_headers(status, headers)

                    if self.remaining == 0:
                        self.finish_request()
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
                    self.finish_request()
                    return

                return

            elif self.state == "close":
                if self.buffer:
                    self.current.push(bytes(self.buffer))
                    self.buffer.clear()

                return

            elif self.state in ("chunk-size", "chunk-data", "chunk-data-crlf", "chunk-trailer"):
                if not self.feed_client_chunked():
                    return

            else:
                return

    def feed_client_chunked(self) -> bool:
        if self.state == "chunk-size":
            end = self.buffer.find(b"\r\n")
            if end == -1:
                return False

            line = bytes(self.buffer[:end]).split(b";", 1)[0].strip()
            del self.buffer[:end + 2]

            try:
                size = int(line, 16)

            except ValueError:
                self.fail_request(ValueError("invalid chunk size"))
                return False

            if size < 0:
                self.fail_request(ValueError("negative chunk size"))
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
                self.fail_request(ValueError("malformed chunk terminator"))
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
                self.finish_request()
                return False

            return True

        return False

    async def request(self, request: Request, streaming: bool) -> Response:
        if self.transport is None:
            raise ConnectionError("connection is not available")

        self.method = request.method
        self.reusable = False
        self.current = StreamState(asyncio.get_running_loop(), self.config.max_body_size)
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
            return await consume_response(self.current, streaming, "HTTP/1.1", self.config.read_timeout, on_done)
        except BaseException:
            self.close()
            self.handler.discard(self)
            raise

    def finish_request(self):
        if self.current is not None:
            self.current.finish()
        self.reusable = self.is_open() and self.keepalive()
        self.current = None
        self.state = "idle"

    def fail_request(self, exc: BaseException):
        if self.current is not None:
            self.current.fail(exc)
            self.current = None
        self.reusable = False
        self.state = "idle"
        self.close()

    def keepalive(self) -> bool:
        if self.headers is None:
            return False
        return "close" not in (self.headers.get("Connection") or "").lower()

    def is_open(self) -> bool:
        return self.transport is not None and not self.protocol.closed

    def close(self):
        self.protocol.close()

    def client_lost(self, exc: BaseException | None):
        if self.current is not None:
            if self.state == "close":
                self.current.finish()
            elif not self.current.ended:
                self.current.fail(exc or ConnectionError("connection closed"))
            self.current = None

class H1Protocol(TCPProtocol):
    """asyncio protocol for plaintext HTTP/1.1 connections (server or client).

    TLS-terminated connections, where ALPN may select HTTP/2, are handled by
    :class:`~kaede.handler.tcp.TCPProtocol` with a factory that chooses between
    :class:`H1Connection` and an HTTP/2 connection.
    """

    def __init__(self, handler, *, is_client: bool = False, tls_context=None, server_name: str | None = None, key: tuple | None = None, authority: str | None = None):
        self._key = key
        self._authority = authority
        super().__init__(is_client=is_client, factory=self._build, tls_context=tls_context, server_name=server_name, handler=handler)

    def _build(self, protocol, alpn):
        return H1Connection(protocol, is_client=self.is_client, key=self._key, authority=self._authority)
