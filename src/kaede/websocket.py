from __future__ import annotations

import os
import zlib
import asyncio
import base64
import hashlib
import struct
from enum import IntEnum
from typing import Any, Protocol, runtime_checkable

@runtime_checkable
class WriteTransport(Protocol):
    def write(self, data: bytes): ...
    def close(self): ...

class WebSocketProtocolError(Exception):
    pass

class Opcode(IntEnum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA

def compute_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()

def generate_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()

def check_accept(key: str, accept_header: str) -> bool:
    return accept_header.strip() == compute_accept(key)

def build_frame(opcode: Opcode, payload: bytes, fin: bool = True, rsv1: bool = False, mask: bool = False) -> bytes:
    b1 = (0x80 if fin else 0x00) | (0x40 if rsv1 else 0x00) | (opcode & 0x0F)
    n = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if n < 126:
        header = bytes([b1, mask_bit | n])
    elif n < 65536:
        header = bytes([b1, mask_bit | 126]) + struct.pack(">H", n)
    else:
        header = bytes([b1, mask_bit | 127]) + struct.pack(">Q", n)

    if mask:
        mask_key = os.urandom(4)
        masked = bytearray(payload)
        for i in range(n):
            masked[i] ^= mask_key[i % 4]
        return header + mask_key + bytes(masked)

    return header + payload

class Frame:
    __slots__ = ("fin", "rsv1", "rsv_other", "opcode", "payload", "masked")

    def __init__(self, fin: bool, rsv1: bool, rsv_other: bool, opcode: Opcode, payload: bytes, masked: bool):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv_other = rsv_other
        self.opcode = opcode
        self.payload = payload
        self.masked = masked

def parse_frames(buf: bytearray, max_payload_size: int | None = None) -> list[Frame]:
    frames: list[Frame] = []

    while len(buf) >= 2:
        b1, b2 = buf[0], buf[1]
        fin = bool(b1 & 0x80)
        rsv1 = bool(b1 & 0x40)
        rsv_other = bool(b1 & 0x30)

        try:
            opcode = Opcode(b1 & 0x0F)
        except ValueError:
            raise WebSocketProtocolError(f"unknown websocket opcode 0x{b1 & 0x0F:x}")

        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        offset = 2

        if length == 126:
            if len(buf) < 4:
                break
            length = struct.unpack_from(">H", buf, 2)[0]
            offset = 4
        elif length == 127:
            if len(buf) < 10:
                break
            length = struct.unpack_from(">Q", buf, 2)[0]
            offset = 10

        if max_payload_size is not None and length > max_payload_size:
            raise ValueError("websocket frame exceeds max message size")

        mask_end = offset + (4 if masked else 0)
        if len(buf) < mask_end + length:
            break

        if masked:
            mask_key = bytes(buf[offset:offset + 4])
            raw = bytearray(buf[mask_end:mask_end + length])
            for i in range(length):
                raw[i] ^= mask_key[i % 4]
            payload = bytes(raw)
        else:
            payload = bytes(buf[mask_end:mask_end + length])

        del buf[:mask_end + length]
        frames.append(Frame(fin, rsv1, rsv_other, opcode, payload, masked))

    return frames

class PerMessageDeflate:
    def __init__(self, server_no_context_takeover: bool = True, client_no_context_takeover: bool = False, server_max_window_bits: int = 15, client_max_window_bits: int = 15):
        self.server_no_context_takeover = server_no_context_takeover
        self.client_no_context_takeover = client_no_context_takeover
        self.server_max_window_bits = server_max_window_bits
        self.client_max_window_bits = client_max_window_bits
        self.compress_context: Any | None = None
        self.decompress_context: Any | None = None

    def compress(self, data: bytes) -> bytes:
        if self.server_no_context_takeover:
            context = zlib.compressobj(wbits=-self.server_max_window_bits)
        else:
            if self.compress_context is None:
                self.compress_context = zlib.compressobj(wbits=-self.server_max_window_bits)
            context = self.compress_context

        compressed = context.compress(data) + context.flush(zlib.Z_SYNC_FLUSH)

        if compressed.endswith(b"\x00\x00\xff\xff"):
            compressed = compressed[:-4]

        return compressed

    def decompress(self, data: bytes, max_size: int | None = None) -> bytes:
        data = data + b"\x00\x00\xff\xff"

        if self.client_no_context_takeover:
            context = zlib.decompressobj(wbits=-self.client_max_window_bits)
        else:
            if self.decompress_context is None:
                self.decompress_context = zlib.decompressobj(wbits=-self.client_max_window_bits)
            context = self.decompress_context

        try:
            if max_size is None:
                return context.decompress(data)

            result = context.decompress(data, max_size)

            if context.unconsumed_tail:
                raise ValueError("decompressed websocket message exceeds max message size")

            return result

        except Exception:
            self.decompress_context = None
            raise

    def response_header(self) -> str:
        parts = ["permessage-deflate"]
        if self.server_no_context_takeover:
            parts.append("server_no_context_takeover")
        if self.client_no_context_takeover:
            parts.append("client_no_context_takeover")
        if self.server_max_window_bits != 15:
            parts.append(f"server_max_window_bits={self.server_max_window_bits}")
        if self.client_max_window_bits != 15:
            parts.append(f"client_max_window_bits={self.client_max_window_bits}")
        return "; ".join(parts)

    @staticmethod
    def from_client_offer(header: str) -> PerMessageDeflate | None:
        for offer in header.split(","):
            parts = [p.strip() for p in offer.split(";")]
            if not parts or parts[0].lower() != "permessage-deflate":
                continue

            params: dict[str, str | bool] = {}
            for part in parts[1:]:
                if "=" in part:
                    k, _, v = part.partition("=")
                    params[k.strip().lower()] = v.strip()
                else:
                    params[part.strip().lower()] = True

            server_max = 15
            v = params.get("server_max_window_bits")
            if v is not None and v is not True:
                try:
                    server_max = max(8, min(15, int(v)))
                except (ValueError, TypeError):
                    pass

            client_max = 15
            v = params.get("client_max_window_bits")
            if v is not None and v is not True:
                try:
                    client_max = max(8, min(15, int(v)))
                except (ValueError, TypeError):
                    pass

            return PerMessageDeflate(server_no_context_takeover=True, client_no_context_takeover="client_no_context_takeover" in params, server_max_window_bits=server_max, client_max_window_bits=client_max)
        return None

class WebSocket:
    def __init__(self, transport: WriteTransport, *, require_masking: bool = True, mask_frames: bool = False, subprotocol: str | None = None, deflate: PerMessageDeflate | None = None, max_message_size: int | None = None):
        self.transport = transport
        self.require_masking = require_masking
        self.mask_frames = mask_frames
        self.subprotocol = subprotocol
        self.deflate = deflate
        self.max_message_size = max_message_size
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.closed = False
        self.fragments: bytearray = bytearray()
        self.fragment_opcode: Opcode | None = None
        self.fragment_rsv1: bool = False

    def decompress(self, payload: bytes, rsv1: bool) -> bytes:
        if rsv1 and self.deflate is not None:
            return self.deflate.decompress(payload, self.max_message_size)
        return payload

    def write(self, data: bytes):
        try:
            self.transport.write(data)
        except Exception:
            self.closed = True

    def feed_frame(self, frame: Frame):
        if self.require_masking and not frame.masked:
            self.close_transport(1002)
            return

        if frame.rsv_other:
            self.close_transport(1002)
            return

        if frame.rsv1 and self.deflate is None:
            self.close_transport(1002)
            return

        if frame.opcode in (Opcode.PING, Opcode.PONG, Opcode.CLOSE):
            if not frame.fin or len(frame.payload) > 125:
                self.close_transport(1002)
                return

        if frame.opcode == Opcode.PING:
            if not self.closed:
                self.write(build_frame(Opcode.PONG, frame.payload, mask=self.mask_frames))
            return

        if frame.opcode == Opcode.PONG:
            return

        if frame.opcode == Opcode.CLOSE:
            if not self.closed:
                self.closed = True
                echo = frame.payload[:2] if len(frame.payload) >= 2 else b""
                self.write(build_frame(Opcode.CLOSE, echo, mask=self.mask_frames))

            try:
                self.transport.close()
            except Exception:
                pass

            self.queue.put_nowait(None)
            return

        if frame.opcode in (Opcode.TEXT, Opcode.BINARY):
            if self.fragment_opcode is not None:
                self.close_transport(1002)
                return

            if frame.fin:
                try:
                    self.queue.put_nowait(self.decompress(frame.payload, frame.rsv1))
                except ValueError:
                    self.close_transport(1009)

            else:
                if self.max_message_size is not None and len(frame.payload) > self.max_message_size:
                    self.close_transport(1009)
                    return
                self.fragments = bytearray(frame.payload)
                self.fragment_opcode = frame.opcode
                self.fragment_rsv1 = frame.rsv1

        elif frame.opcode == Opcode.CONTINUATION:
            if self.fragment_opcode is None:
                self.close_transport(1002)
                return

            if self.max_message_size is not None and len(self.fragments) + len(frame.payload) > self.max_message_size:
                self.close_transport(1009)
                return

            self.fragments.extend(frame.payload)

            if frame.fin:
                try:
                    self.queue.put_nowait(self.decompress(bytes(self.fragments), self.fragment_rsv1))
                except ValueError:
                    self.close_transport(1009)
                    return

                self.fragments = bytearray()
                self.fragment_opcode = None
                self.fragment_rsv1 = False

    def close_transport(self, code: int):
        if not self.closed:
            self.closed = True
            self.write(build_frame(Opcode.CLOSE, struct.pack(">H", code), mask=self.mask_frames))

            try:
                self.transport.close()
            except Exception:
                pass

            self.queue.put_nowait(None)

    async def ping(self, payload: bytes = b""):
        if self.closed:
            return
        self.write(build_frame(Opcode.PING, payload, mask=self.mask_frames))

    async def receive(self) -> bytes | None:
        return await self.queue.get()

    async def send(self, data: bytes | str):
        if self.closed:
            return

        if isinstance(data, str):
            payload = data.encode("utf-8")
            if self.deflate is not None:
                self.write(build_frame(Opcode.TEXT, self.deflate.compress(payload), rsv1=True, mask=self.mask_frames))
            else:
                self.write(build_frame(Opcode.TEXT, payload, mask=self.mask_frames))

        else:
            if self.deflate is not None:
                self.write(build_frame(Opcode.BINARY, self.deflate.compress(data), rsv1=True, mask=self.mask_frames))
            else:
                self.write(build_frame(Opcode.BINARY, data, mask=self.mask_frames))

    async def close(self, code: int = 1000, reason: str = ""):
        if self.closed:
            return
        self.closed = True
        payload = struct.pack(">H", code) + reason.encode("utf-8")
        self.write(build_frame(Opcode.CLOSE, payload, mask=self.mask_frames))
        self.queue.put_nowait(None)
