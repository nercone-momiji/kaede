from __future__ import annotations

import ctypes
import ipaddress

from ..tls.models import TLSServerConfig, TLSClientConfig, TLSInfo
from ..tls.openssl import OpenSSL, TLSError, VOID_P, LEVEL_INITIAL, LEVEL_EARLY, LEVEL_HANDSHAKE, LEVEL_APPLICATION, DIRECTION_READ, DIRECTION_WRITE, TLS1_3_VERSION, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE

FUNC_CRYPTO_SEND = 2001
FUNC_CRYPTO_RECV_RCD = 2002
FUNC_CRYPTO_RELEASE_RCD = 2003
FUNC_YIELD_SECRET = 2004
FUNC_GOT_TRANSPORT_PARAMS = 2005
FUNC_ALERT = 2006

class OSSL_DISPATCH(ctypes.Structure):
    _fields_ = [("function_id", ctypes.c_int), ("function", ctypes.c_void_p)]

CB_CRYPTO_SEND = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, VOID_P, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t), VOID_P)
CB_CRYPTO_RECV_RCD = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(ctypes.c_size_t), VOID_P)
CB_CRYPTO_RELEASE_RCD = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.c_size_t, VOID_P)
CB_YIELD_SECRET = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.c_uint32, ctypes.c_int, VOID_P, ctypes.c_size_t, VOID_P)
CB_GOT_TRANSPORT_PARAMS = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, VOID_P, ctypes.c_size_t, VOID_P)
CB_ALERT = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.c_ubyte, VOID_P)
# void (*)(const SSL *ssl, const char *line) — fires for every TLS secret derived
CB_KEYLOG = ctypes.CFUNCTYPE(None, VOID_P, ctypes.c_char_p)

QuicTLSError = TLSError

class QuicTLSServerContext:
    def __init__(self, lib: OpenSSL, ctx: int, keepalive: list, alpn: tuple[str, ...], *, enable_0rtt: bool = False):
        self.lib = lib
        self.ctx = ctx
        self.keepalive = keepalive
        self.alpn = alpn
        self._enable_0rtt = enable_0rtt

    @classmethod
    def for_server(cls, config: TLSServerConfig, *, alpn: tuple[str, ...] = ("h3",), enable_0rtt: bool = True) -> "QuicTLSServerContext":
        lib = OpenSSL.get()
        ctx, keepalive = lib.new_context(is_client=False, alpn=alpn, groups=config.groups, ciphers=config.ciphers, min_version=TLS1_3_VERSION, max_version=TLS1_3_VERSION)
        lib.apply_server_config(ctx, config)
        if enable_0rtt:
            lib.enable_early_data(ctx)
            cb = CB_KEYLOG(server_keylog_cb)
            keepalive.append(cb)
            lib.ssl.SSL_CTX_set_keylog_callback(ctx, ctypes.cast(cb, VOID_P))
        return cls(lib, ctx, keepalive, alpn, enable_0rtt=enable_0rtt)

    def connection(self, *, transport_params: bytes = b"") -> "QuicTLS":
        obj = QuicTLS(self.ctx, self.lib, is_client=False, transport_params=transport_params, owns_ctx=False)
        if self._enable_0rtt:
            self.lib.enable_quic_early_data(obj.SSL)
        return obj

    def free(self):
        ctx = getattr(self, "ctx", None)
        if ctx:
            try:
                self.lib.ssl.SSL_CTX_free(ctx)
            except Exception:
                pass
            self.ctx = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

class QuicTLS:
    ssl_registry: "dict[int, QuicTLS]" = {}

    def __init__(self, ctx_ptr: int, lib: OpenSSL, *, is_client: bool, owns_ctx: bool = True, server_name: str | None = None, verify_hostname: bool = False, transport_params: bytes = b"", keepalive=()):
        self.lib = lib
        self.ctx = ctx_ptr
        self.owns_ctx = owns_ctx
        self.keepalive = list(keepalive)
        self.is_client = is_client
        self.server_name = server_name
        self.verify_hostname = verify_hostname
        self.sni: bytes | None = None

        self.secrets: dict[tuple[int, int], bytes] = {}
        self.peer_transport_params: bytes = b""
        self.handshake_complete: bool = False
        self.alert: int | None = None

        self.read_level = LEVEL_INITIAL
        self.write_level = LEVEL_INITIAL
        self.recv: dict[int, bytearray] = {LEVEL_INITIAL: bytearray(), LEVEL_EARLY: bytearray(), LEVEL_HANDSHAKE: bytearray(), LEVEL_APPLICATION: bytearray()}
        self.outgoing: list[tuple[int, bytes]] = []
        self.inflight: ctypes.Array | None = None
        self.inflight_level: int | None = None
        self.callback_error: BaseException | None = None

        ssl = self.lib.ssl
        self.SSL = ssl.SSL_new(ctx_ptr)

        if not self.SSL:
            if owns_ctx:
                ssl.SSL_CTX_free(ctx_ptr)
            self.ctx = None
            raise TLSError(f"SSL_new failed: {self.lib.errors()}")

        QuicTLS.ssl_registry[self.SSL] = self
        self.install_callbacks()

        self.tp_buf = ctypes.create_string_buffer(transport_params, len(transport_params)) if transport_params else None
        tp_ptr = ctypes.cast(self.tp_buf, VOID_P) if self.tp_buf is not None else None
        if ssl.SSL_set_quic_tls_transport_params(self.SSL, tp_ptr, len(transport_params)) != 1:
            raise TLSError(f"SSL_set_quic_tls_transport_params failed: {self.lib.errors()}")

        if is_client:
            ssl.SSL_set_connect_state(self.SSL)

            if server_name:
                try:
                    ipaddress.ip_address(server_name)
                    is_ip = True
                except ValueError:
                    is_ip = False

                if not is_ip:
                    try:
                        self.sni = server_name.encode("idna")
                    except (UnicodeError, UnicodeDecodeError):
                        self.sni = server_name.encode("ascii")

                    ssl.SSL_ctrl(self.SSL, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, ctypes.cast(ctypes.c_char_p(self.sni), VOID_P))

                    if verify_hostname:
                        ssl.SSL_set1_host(self.SSL, self.sni)

        else:
            ssl.SSL_set_accept_state(self.SSL)

    def install_callbacks(self):
        send = CB_CRYPTO_SEND(self.on_crypto_send)
        recv = CB_CRYPTO_RECV_RCD(self.on_crypto_recv_rcd)
        release = CB_CRYPTO_RELEASE_RCD(self.on_crypto_release_rcd)
        secret = CB_YIELD_SECRET(self.on_yield_secret)
        params = CB_GOT_TRANSPORT_PARAMS(self.on_got_transport_params)
        alert = CB_ALERT(self.on_alert)

        self.cb_refs = [send, recv, release, secret, params, alert]

        entries = [
            (FUNC_CRYPTO_SEND, send),
            (FUNC_CRYPTO_RECV_RCD, recv),
            (FUNC_CRYPTO_RELEASE_RCD, release),
            (FUNC_YIELD_SECRET, secret),
            (FUNC_GOT_TRANSPORT_PARAMS, params),
            (FUNC_ALERT, alert),
            (0, None)
        ]

        self.dispatch = (OSSL_DISPATCH * len(entries))()
        for i, (fid, fn) in enumerate(entries):
            self.dispatch[i].function_id = fid
            self.dispatch[i].function = ctypes.cast(fn, VOID_P) if fn is not None else None

        if self.lib.ssl.SSL_set_quic_tls_cbs(self.SSL, ctypes.cast(self.dispatch, VOID_P), None) != 1:
            raise TLSError(f"SSL_set_quic_tls_cbs failed: {self.lib.errors()}")

    def on_crypto_send(self, ssl_p, buf, buf_len, consumed_p, arg):
        try:
            data = ctypes.string_at(buf, buf_len) if buf_len else b""
            if data:
                self.outgoing.append((self.write_level, data))
            consumed_p[0] = buf_len
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_crypto_recv_rcd(self, ssl_p, buf_pp, bytes_read_p, arg):
        try:
            pending = self.recv[self.read_level]
            if not pending:
                bytes_read_p[0] = 0
                return 1
            self.inflight = (ctypes.c_char * len(pending)).from_buffer_copy(bytes(pending))
            self.inflight_level = self.read_level
            buf_pp[0] = ctypes.cast(self.inflight, VOID_P)
            bytes_read_p[0] = len(pending)
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_crypto_release_rcd(self, ssl_p, bytes_read, arg):
        try:
            if self.inflight_level is not None:
                del self.recv[self.inflight_level][:bytes_read]
            self.inflight = None
            self.inflight_level = None
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_yield_secret(self, ssl_p, prot_level, direction, secret, secret_len, arg):
        try:
            self.secrets[(int(prot_level), int(direction))] = ctypes.string_at(secret, secret_len) if secret_len else b""
            if direction == DIRECTION_READ:
                self.read_level = int(prot_level)
            else:
                self.write_level = int(prot_level)
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_got_transport_params(self, ssl_p, params, params_len, arg):
        try:
            self.peer_transport_params = ctypes.string_at(params, params_len) if params_len else b""
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_alert(self, ssl_p, alert_code, arg):
        try:
            self.alert = int(alert_code)
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def provide_crypto(self, level: int, data: bytes):
        if data:
            self.recv[level].extend(data)

    def advance(self) -> list[tuple[int, bytes]]:
        ssl = self.lib.ssl
        ret = ssl.SSL_do_handshake(self.SSL)
        self.check_callback_error()

        if ret == 1:
            self.handshake_complete = True
            self.pump_post_handshake()
        else:
            err = ssl.SSL_get_error(self.SSL, ret)
            if err not in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                raise TLSError(f"TLS handshake failed (SSL_get_error={err}, alert={self.alert}): {self.lib.errors()}")

        out = self.outgoing
        self.outgoing = []
        return out

    def pump_post_handshake(self):
        ssl = self.lib.ssl
        buf = ctypes.create_string_buffer(1)
        for _ in range(8):
            ret = ssl.SSL_read(self.SSL, ctypes.cast(buf, VOID_P), 0)
            self.check_callback_error()
            if ret > 0:
                continue
            break

        if self.is_client:
            session_bytes = self.lib.serialize_session(self.SSL)
            if session_bytes:
                self._session_bytes = session_bytes

    def reset_for_retry(self):
        ssl = self.lib.ssl
        if self.SSL:
            QuicTLS.ssl_registry.pop(self.SSL, None)
            ssl.SSL_free(self.SSL)
            self.SSL = None

        self.SSL = ssl.SSL_new(self.ctx)
        if not self.SSL:
            raise TLSError("SSL_new failed during Retry reset")

        QuicTLS.ssl_registry[self.SSL] = self
        self.install_callbacks()

        if self.tp_buf is not None:
            tp_ptr = ctypes.cast(self.tp_buf, VOID_P)
            if ssl.SSL_set_quic_tls_transport_params(self.SSL, tp_ptr, len(self.tp_buf)) != 1:
                raise TLSError("SSL_set_quic_tls_transport_params failed during Retry reset")

        ssl.SSL_set_connect_state(self.SSL)
        if self.sni:
            ssl.SSL_ctrl(self.SSL, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                         ctypes.cast(ctypes.c_char_p(self.sni), VOID_P))
            if self.verify_hostname:
                ssl.SSL_set1_host(self.SSL, self.sni)

        self.secrets = {}
        self.peer_transport_params = b""
        self.handshake_complete = False
        self.alert = None
        self.read_level = LEVEL_INITIAL
        self.write_level = LEVEL_INITIAL
        self.recv = {LEVEL_INITIAL: bytearray(), LEVEL_EARLY: bytearray(), LEVEL_HANDSHAKE: bytearray(), LEVEL_APPLICATION: bytearray()}
        self.outgoing = []
        self.inflight = None
        self.inflight_level = None
        self.callback_error = None

    def check_callback_error(self):
        if self.callback_error is not None:
            exc = self.callback_error
            self.callback_error = None
            raise TLSError(f"QUIC-TLS callback raised: {exc!r}")

    def read_secret(self, level: int) -> bytes | None:
        return self.secrets.get((level, DIRECTION_READ))

    def write_secret(self, level: int) -> bytes | None:
        return self.secrets.get((level, DIRECTION_WRITE))

    def alpn(self) -> str | None:
        return self.lib.selected_alpn(self.SSL)

    def cipher_name(self) -> str | None:
        return self.lib.cipher_name(self.SSL)

    def group_name(self) -> str | None:
        return self.lib.group_name(self.SSL)

    def get_session_bytes(self) -> bytes | None:
        return getattr(self, "_session_bytes", None)

    def info(self) -> TLSInfo:
        return self.lib.tls_info(self.SSL)

    def free(self):
        ssl_handle = getattr(self, "SSL", None)

        if ssl_handle is not None:
            QuicTLS.ssl_registry.pop(ssl_handle, None)

            try:
                self.lib.ssl.SSL_free(ssl_handle)
            except Exception:
                pass

            self.SSL = None

        if getattr(self, "owns_ctx", True) and getattr(self, "ctx", None):
            try:
                self.lib.ssl.SSL_CTX_free(self.ctx)
            except Exception:
                pass
            self.ctx = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @classmethod
    def for_server(cls, config: TLSServerConfig, *, alpn: tuple[str, ...] = ("h3",), transport_params: bytes = b"", enable_0rtt: bool = True) -> "QuicTLS":
        lib = OpenSSL.get()
        ctx, keepalive = lib.new_context(is_client=False, alpn=alpn, groups=config.groups, ciphers=config.ciphers, min_version=TLS1_3_VERSION, max_version=TLS1_3_VERSION)
        lib.apply_server_config(ctx, config)

        if enable_0rtt:
            lib.enable_early_data(ctx)

        return cls(ctx, lib, is_client=False, transport_params=transport_params, keepalive=keepalive)

    @classmethod
    def for_client(cls, config: TLSClientConfig, server_name: str, *, alpn: tuple[str, ...] = ("h3",), transport_params: bytes = b"", session_bytes: bytes | None = None) -> "QuicTLS":
        lib = OpenSSL.get()
        ctx, keepalive = lib.new_context(is_client=True, alpn=alpn, groups=config.groups, ciphers=config.ciphers, min_version=TLS1_3_VERSION, max_version=TLS1_3_VERSION)
        lib.enable_client_sessions(ctx)
        verify_hostname = lib.apply_client_config(ctx, config)
        obj = cls(ctx, lib, is_client=True, server_name=server_name, verify_hostname=verify_hostname, transport_params=transport_params, keepalive=keepalive)

        if session_bytes:
            lib.deserialize_and_set_session(obj.SSL, session_bytes)
            lib.enable_quic_early_data(obj.SSL)

        return obj


def server_keylog_cb(ssl_ptr: int, line: bytes) -> None:
    if not line or ssl_ptr is None:
        return
    try:
        line_str = line.decode("ascii", "replace")
    except Exception:
        return
    if not line_str.startswith("CLIENT_EARLY_TRAFFIC_SECRET "):
        return
    parts = line_str.split()
    if len(parts) != 3:
        return
    try:
        secret = bytes.fromhex(parts[2])
    except ValueError:
        return
    quic_tls = QuicTLS.ssl_registry.get(ssl_ptr)
    if quic_tls is not None:
        quic_tls.secrets[(LEVEL_EARLY, DIRECTION_READ)] = secret
