from __future__ import annotations

import asyncio

from ..tls import TLS

class TLSTransport:
    def __init__(self, raw: asyncio.Transport, engine: TLS):
        self.raw = raw
        self.engine = engine

    def write(self, data: bytes):
        if self.raw.is_closing():
            return
        if data:
            self.engine.write(data)
        out = self.engine.drain()
        if out:
            self.raw.write(out)

    def is_closing(self) -> bool:
        return self.raw.is_closing()

    def close(self):
        self.raw.close()

    def pause_reading(self):
        self.raw.pause_reading()

    def resume_reading(self):
        self.raw.resume_reading()

    def get_extra_info(self, name, default=None):
        return self.raw.get_extra_info(name, default)

def tls_emit(raw: asyncio.Transport, data: bytes):
    if data and not raw.is_closing():
        raw.write(data)

def tls_start(engine: TLS, raw: asyncio.Transport):
    engine.do_handshake()
    tls_emit(raw, engine.drain())

def tls_feed(engine: TLS, raw: asyncio.Transport, data: bytes) -> tuple[bool, bytes]:
    engine.receive(data)

    became_ready = False
    if not engine.handshake_complete:
        done = engine.do_handshake()
        tls_emit(raw, engine.drain())
        if not done:
            return False, b""
        became_ready = True

    plaintext = engine.read()
    tls_emit(raw, engine.drain())
    return became_ready, plaintext
