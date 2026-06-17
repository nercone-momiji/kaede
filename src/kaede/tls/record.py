from __future__ import annotations

import ctypes

from .models import TLSServerConfig, TLSClientConfig, TLSInfo
from .openssl import OpenSSL, TLSError, VOID_P, TLS1_3_VERSION, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN, BIO_CTRL_PENDING

CHUNK = 16384

class TLSContext:
    def __init__(self, lib: OpenSSL, ctx: int, keepalive: list, *, is_client: bool, verify_hostname: bool = False):
        self.lib = lib
        self.ctx = ctx
        self.keepalive = keepalive
        self.is_client = is_client
        self.verify_hostname = verify_hostname

    @classmethod
    def for_server(cls, config: TLSServerConfig, *, alpn: tuple[str, ...]) -> "TLSContext":
        lib = OpenSSL.get()
        ctx, keepalive = lib.new_context(is_client=False, alpn=alpn, groups=config.groups, ciphers=config.ciphers, min_version=int(config.minimum_version), max_version=TLS1_3_VERSION)
        lib.apply_server_config(ctx, config)
        return cls(lib, ctx, keepalive, is_client=False)

    @classmethod
    def for_client(cls, config: TLSClientConfig, *, alpn: tuple[str, ...]) -> "TLSContext":
        lib = OpenSSL.get()
        ctx, keepalive = lib.new_context(is_client=True, alpn=alpn, groups=config.groups, ciphers=config.ciphers, min_version=int(config.minimum_version), max_version=TLS1_3_VERSION)
        verify_hostname = lib.apply_client_config(lib, ctx, config)
        return cls(lib, ctx, keepalive, is_client=True, verify_hostname=verify_hostname)

    def connection(self, server_name: str | None = None) -> "TLS":
        return TLS(self, server_name=server_name)

    def free(self):
        if self.ctx:
            self.lib.ssl.SSL_CTX_free(self.ctx)
            self.ctx = 0

class TLS:
    def __init__(self, context: TLSContext, *, server_name: str | None = None):
        self.context = context
        self.lib = context.lib

        ssl = self.lib.ssl
        crypto = self.lib.crypto

        self.SSL = ssl.SSL_new(context.ctx)
        if not self.SSL:
            raise TLSError(f"SSL_new failed: {self.lib.errors()}")

        method = crypto.BIO_s_mem()
        self.rbio = crypto.BIO_new(method)
        self.wbio = crypto.BIO_new(method)
        if not self.rbio or not self.wbio:
            ssl.SSL_free(self.SSL)
            self.SSL = None
            raise TLSError("BIO_new(BIO_s_mem()) failed")

        ssl.SSL_set_bio(self.SSL, self.rbio, self.wbio)

        self.handshake_complete = False
        self.closed = False
        self.server_name = server_name

        if context.is_client:
            ssl.SSL_set_connect_state(self.SSL)
            if server_name:
                self.sni = server_name.encode("idna")
                ssl.SSL_ctrl(self.SSL, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, ctypes.cast(ctypes.c_char_p(self.sni), VOID_P))
                if context.verify_hostname:
                    ssl.SSL_set1_host(self.SSL, self.sni)
        else:
            ssl.SSL_set_accept_state(self.SSL)

    def receive(self, data: bytes):
        if not data:
            return
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        offset = 0
        while offset < len(data):
            ret = self.lib.crypto.BIO_write(self.rbio, ctypes.cast(ctypes.byref(buf, offset), VOID_P), len(data) - offset)
            if ret <= 0:
                raise TLSError("BIO_write into rbio failed")
            offset += ret

    def do_handshake(self) -> bool:
        ssl = self.lib.ssl
        ret = ssl.SSL_do_handshake(self.SSL)
        if ret == 1:
            self.handshake_complete = True
            return True
        err = ssl.SSL_get_error(self.SSL, ret)
        if err in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            return False
        raise TLSError(f"TLS handshake failed (SSL_get_error={err}): {self.lib.errors()}")

    def read(self) -> bytes:
        ssl = self.lib.ssl
        out = bytearray()
        buf = ctypes.create_string_buffer(CHUNK)
        while True:
            ret = ssl.SSL_read(self.SSL, ctypes.cast(buf, VOID_P), CHUNK)
            if ret > 0:
                out += buf.raw[:ret]
                continue
            err = ssl.SSL_get_error(self.SSL, ret)
            if err in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                break
            self.closed = True
            break
        return bytes(out)

    def write(self, data: bytes):
        if not data:
            return
        ssl = self.lib.ssl
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        offset = 0
        while offset < len(data):
            ret = ssl.SSL_write(self.SSL, ctypes.cast(ctypes.byref(buf, offset), VOID_P), len(data) - offset)
            if ret > 0:
                offset += ret
                continue
            err = ssl.SSL_get_error(self.SSL, ret)
            if err in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                continue
            raise TLSError(f"SSL_write failed (SSL_get_error={err}): {self.lib.errors()}")

    def drain(self) -> bytes:
        crypto = self.lib.crypto
        out = bytearray()
        buf = ctypes.create_string_buffer(CHUNK)
        while True:
            ret = crypto.BIO_read(self.wbio, ctypes.cast(buf, VOID_P), CHUNK)
            if ret <= 0:
                break
            out += buf.raw[:ret]
        return bytes(out)

    def pending(self) -> int:
        return int(self.lib.crypto.BIO_ctrl(self.wbio, BIO_CTRL_PENDING, 0, None))

    def shutdown(self):
        if self.SSL:
            self.lib.ssl.SSL_shutdown(self.SSL)

    def selected_alpn(self) -> str | None:
        return self.lib.selected_alpn(self.SSL)

    def info(self) -> TLSInfo:
        return self.lib.tls_info(self.SSL)

    def free(self):
        if getattr(self, "SSL", None):
            self.lib.ssl.SSL_free(self.SSL)
            self.SSL = None
            self.rbio = None
            self.wbio = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass
