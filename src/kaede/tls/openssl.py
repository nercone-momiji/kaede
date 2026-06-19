from __future__ import annotations

import os
import sys
import glob
import ctypes
import ctypes.util

from .models import Group, Cipher, TLSServerConfig, TLSClientConfig, TLSInfo, CIPHER_MAP, GROUP_MAP, VERSION_MAP

LEVEL_INITIAL = 0
LEVEL_EARLY = 1
LEVEL_HANDSHAKE = 2
LEVEL_APPLICATION = 3

DIRECTION_READ = 0
DIRECTION_WRITE = 1

SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
SSL_CTRL_SET_MIN_PROTO_VERSION = 123
SSL_CTRL_SET_MAX_PROTO_VERSION = 124
TLSEXT_NAMETYPE_host_name = 0

TLS1_2_VERSION = 0x0303
TLS1_3_VERSION = 0x0304

SSL_FILETYPE_PEM = 1

SSL_VERIFY_NONE = 0
SSL_VERIFY_PEER = 1
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2

SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_ZERO_RETURN = 6

SSL_TLSEXT_ERR_OK = 0
SSL_TLSEXT_ERR_NOACK = 3

BIO_CTRL_PENDING = 10

SSL_SESS_CACHE_OFF = 0x0000
SSL_SESS_CACHE_CLIENT = 0x0001
SSL_SESS_CACHE_SERVER = 0x0002
SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080
SSL_CTRL_SET_SESS_CACHE_MODE = 44

SSL_CTRL_OPTIONS = 32
SSL_OP_NO_ANTI_REPLAY = 0x40000000

VOID_P = ctypes.c_void_p

CB_ALPN_SELECT = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(ctypes.c_ubyte), VOID_P, ctypes.c_uint, VOID_P)

class TLSError(Exception):
    pass

class OpenSSL:
    instance: "OpenSSL | None" = None

    def __init__(self):
        self.ssl: ctypes.CDLL | None = None
        self.crypto: ctypes.CDLL | None = None
        self.path: str | None = None

        for path in OpenSSL.candidate_libssl_paths():
            try:
                lib = ctypes.CDLL(path)
            except OSError:
                continue

            if not hasattr(lib, "SSL_set_quic_tls_cbs"):
                continue

            self.ssl = lib
            self.path = path
            break

        if self.ssl is None:
            raise TLSError("could not load an OpenSSL libssl exporting SSL_set_quic_tls_cbs; OpenSSL 3.5+ is required (set KAEDE_LIBSSL to override)")

        if self.path:
            crypto_path = self.path.replace("libssl", "libcrypto")

            try:
                self.crypto = ctypes.CDLL(crypto_path)
            except OSError:
                self.crypto = None

        if self.crypto is None:
            raise TLSError(f"could not load the matching libcrypto for {self.path!r}; required for BIO/error handling (set KAEDE_LIBSSL to override)")

        self.configure()

    @classmethod
    def get(cls) -> "OpenSSL":
        if cls.instance is None:
            cls.instance = OpenSSL()
        return cls.instance

    def configure(self):
        s = self.ssl
        c = self.crypto

        s.TLS_method.restype = VOID_P
        s.TLS_method.argtypes = []
        s.SSL_CTX_new.restype = VOID_P
        s.SSL_CTX_new.argtypes = [VOID_P]
        s.SSL_CTX_free.restype = None
        s.SSL_CTX_free.argtypes = [VOID_P]
        s.SSL_CTX_ctrl.restype = ctypes.c_long
        s.SSL_CTX_ctrl.argtypes = [VOID_P, ctypes.c_int, ctypes.c_long, VOID_P]
        s.SSL_CTX_use_certificate_chain_file.restype = ctypes.c_int
        s.SSL_CTX_use_certificate_chain_file.argtypes = [VOID_P, ctypes.c_char_p]
        s.SSL_CTX_use_PrivateKey_file.restype = ctypes.c_int
        s.SSL_CTX_use_PrivateKey_file.argtypes = [VOID_P, ctypes.c_char_p, ctypes.c_int]
        s.SSL_CTX_set_alpn_protos.restype = ctypes.c_int
        s.SSL_CTX_set_alpn_protos.argtypes = [VOID_P, VOID_P, ctypes.c_uint]
        s.SSL_CTX_set_alpn_select_cb.restype = None
        s.SSL_CTX_set_alpn_select_cb.argtypes = [VOID_P, VOID_P, VOID_P]
        s.SSL_CTX_set_verify.restype = None
        s.SSL_CTX_set_verify.argtypes = [VOID_P, ctypes.c_int, VOID_P]
        s.SSL_CTX_load_verify_locations.restype = ctypes.c_int
        s.SSL_CTX_load_verify_locations.argtypes = [VOID_P, ctypes.c_char_p, ctypes.c_char_p]
        s.SSL_CTX_set_default_verify_paths.restype = ctypes.c_int
        s.SSL_CTX_set_default_verify_paths.argtypes = [VOID_P]
        if hasattr(s, "SSL_CTX_set1_groups_list"):
            s.SSL_CTX_set1_groups_list.restype = ctypes.c_int
            s.SSL_CTX_set1_groups_list.argtypes = [VOID_P, ctypes.c_char_p]
        s.SSL_CTX_set_cipher_list.restype = ctypes.c_int
        s.SSL_CTX_set_cipher_list.argtypes = [VOID_P, ctypes.c_char_p]
        if hasattr(s, "SSL_CTX_set_ciphersuites"):
            s.SSL_CTX_set_ciphersuites.restype = ctypes.c_int
            s.SSL_CTX_set_ciphersuites.argtypes = [VOID_P, ctypes.c_char_p]

        s.SSL_new.restype = VOID_P
        s.SSL_new.argtypes = [VOID_P]
        s.SSL_free.restype = None
        s.SSL_free.argtypes = [VOID_P]
        s.SSL_set_connect_state.restype = None
        s.SSL_set_connect_state.argtypes = [VOID_P]
        s.SSL_set_accept_state.restype = None
        s.SSL_set_accept_state.argtypes = [VOID_P]
        s.SSL_do_handshake.restype = ctypes.c_int
        s.SSL_do_handshake.argtypes = [VOID_P]
        s.SSL_get_error.restype = ctypes.c_int
        s.SSL_get_error.argtypes = [VOID_P, ctypes.c_int]
        s.SSL_read.restype = ctypes.c_int
        s.SSL_read.argtypes = [VOID_P, VOID_P, ctypes.c_int]
        s.SSL_write.restype = ctypes.c_int
        s.SSL_write.argtypes = [VOID_P, VOID_P, ctypes.c_int]
        s.SSL_pending.restype = ctypes.c_int
        s.SSL_pending.argtypes = [VOID_P]
        s.SSL_shutdown.restype = ctypes.c_int
        s.SSL_shutdown.argtypes = [VOID_P]
        s.SSL_ctrl.restype = ctypes.c_long
        s.SSL_ctrl.argtypes = [VOID_P, ctypes.c_int, ctypes.c_long, VOID_P]
        s.SSL_set1_host.restype = ctypes.c_int
        s.SSL_set1_host.argtypes = [VOID_P, ctypes.c_char_p]
        s.SSL_set_bio.restype = None
        s.SSL_set_bio.argtypes = [VOID_P, VOID_P, VOID_P]

        s.SSL_set_quic_tls_cbs.restype = ctypes.c_int
        s.SSL_set_quic_tls_cbs.argtypes = [VOID_P, VOID_P, VOID_P]
        s.SSL_set_quic_tls_transport_params.restype = ctypes.c_int
        s.SSL_set_quic_tls_transport_params.argtypes = [VOID_P, VOID_P, ctypes.c_size_t]

        s.SSL_get0_alpn_selected.restype = None
        s.SSL_get0_alpn_selected.argtypes = [VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(ctypes.c_uint)]
        s.SSL_get_current_cipher.restype = VOID_P
        s.SSL_get_current_cipher.argtypes = [VOID_P]
        s.SSL_CIPHER_get_name.restype = ctypes.c_char_p
        s.SSL_CIPHER_get_name.argtypes = [VOID_P]
        s.SSL_get_version.restype = ctypes.c_char_p
        s.SSL_get_version.argtypes = [VOID_P]
        if hasattr(s, "SSL_get0_group_name"):
            s.SSL_get0_group_name.restype = ctypes.c_char_p
            s.SSL_get0_group_name.argtypes = [VOID_P]

        s.SSL_get1_session.restype = VOID_P
        s.SSL_get1_session.argtypes = [VOID_P]
        s.SSL_set_session.restype = ctypes.c_int
        s.SSL_set_session.argtypes = [VOID_P, VOID_P]
        s.SSL_SESSION_free.restype = None
        s.SSL_SESSION_free.argtypes = [VOID_P]
        s.i2d_SSL_SESSION.restype = ctypes.c_int
        s.i2d_SSL_SESSION.argtypes = [VOID_P, ctypes.POINTER(VOID_P)]
        s.d2i_SSL_SESSION.restype = VOID_P
        s.d2i_SSL_SESSION.argtypes = [VOID_P, ctypes.POINTER(VOID_P), ctypes.c_long]
        if hasattr(s, "SSL_CTX_set_max_early_data"):
            s.SSL_CTX_set_max_early_data.restype = ctypes.c_int
            s.SSL_CTX_set_max_early_data.argtypes = [VOID_P, ctypes.c_uint32]
        if hasattr(s, "SSL_CTX_set_recv_max_early_data"):
            s.SSL_CTX_set_recv_max_early_data.restype = ctypes.c_int
            s.SSL_CTX_set_recv_max_early_data.argtypes = [VOID_P, ctypes.c_uint32]

        if hasattr(s, "SSL_set_quic_tls_early_data_enabled"):
            s.SSL_set_quic_tls_early_data_enabled.restype = ctypes.c_int
            s.SSL_set_quic_tls_early_data_enabled.argtypes = [VOID_P, ctypes.c_int]

        s.SSL_CTX_set_keylog_callback.restype = None
        s.SSL_CTX_set_keylog_callback.argtypes = [VOID_P, VOID_P]

        if hasattr(c, "OPENSSL_free"):
            c.OPENSSL_free.restype = None
            c.OPENSSL_free.argtypes = [VOID_P]

        c.BIO_new.restype = VOID_P
        c.BIO_new.argtypes = [VOID_P]
        c.BIO_s_mem.restype = VOID_P
        c.BIO_s_mem.argtypes = []
        c.BIO_free.restype = ctypes.c_int
        c.BIO_free.argtypes = [VOID_P]
        c.BIO_write.restype = ctypes.c_int
        c.BIO_write.argtypes = [VOID_P, VOID_P, ctypes.c_int]
        c.BIO_read.restype = ctypes.c_int
        c.BIO_read.argtypes = [VOID_P, VOID_P, ctypes.c_int]
        c.BIO_ctrl.restype = ctypes.c_long
        c.BIO_ctrl.argtypes = [VOID_P, ctypes.c_int, ctypes.c_long, VOID_P]
        c.ERR_get_error.restype = ctypes.c_ulong
        c.ERR_get_error.argtypes = []
        c.ERR_error_string_n.restype = None
        c.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

    def errors(self) -> str:
        messages: list[str] = []

        while True:
            code = self.crypto.ERR_get_error()
            if code == 0:
                break

            buf = ctypes.create_string_buffer(256)
            self.crypto.ERR_error_string_n(code, buf, len(buf))
            messages.append(buf.value.decode("ascii", "replace"))

        return "; ".join(messages)

    @staticmethod
    def candidate_libssl_paths() -> list[str]:
        paths: list[str] = []

        env = os.environ.get("KAEDE_LIBSSL")
        if env:
            paths.append(env)

        if sys.platform == "darwin":
            patterns = [
                "/opt/homebrew/opt/openssl@3*/lib/libssl.dylib",
                "/opt/homebrew/lib/libssl.dylib",
                "/usr/local/opt/openssl@3*/lib/libssl.dylib",
                "/usr/local/lib/libssl.dylib",
            ]

            for pattern in patterns:
                paths.extend(sorted(glob.glob(pattern), reverse=True))

        else:
            patterns = [
                "/usr/lib/*/libssl.so.3",
                "/usr/lib64/libssl.so.3",
                "/usr/lib/libssl.so.3",
                "/lib/*/libssl.so.3",
                "/usr/local/lib/libssl.so.3",
            ]

            for pattern in patterns:
                paths.extend(sorted(glob.glob(pattern), reverse=True))

            for name in ("libssl.so.3", "libssl.so"):
                paths.append(name)

        found = ctypes.util.find_library("ssl")
        if found:
            paths.append(found)

        seen: set[str] = set()
        unique: list[str] = []

        for path in paths:
            if path not in seen:
                seen.add(path)
                unique.append(path)

        return unique

    def new_context(self, *, is_client: bool, alpn: tuple[str, ...], groups: list[Group], ciphers: list[Cipher], min_version: int, max_version: int) -> tuple[int, list]:
        ssl = self.ssl
        ctx = ssl.SSL_CTX_new(ssl.TLS_method())

        if not ctx:
            raise TLSError(f"SSL_CTX_new failed: {self.errors()}")

        ssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, min_version, None)
        ssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, max_version, None)

        keepalive: list = []

        if alpn:
            wire = alpn_wire(alpn)
            buf = ctypes.create_string_buffer(wire, len(wire))
            keepalive.append(buf)
            if is_client:
                if ssl.SSL_CTX_set_alpn_protos(ctx, ctypes.cast(buf, VOID_P), len(wire)) != 0:
                    ssl.SSL_CTX_free(ctx)
                    raise TLSError("SSL_CTX_set_alpn_protos failed")
            else:
                offered = list(alpn)

                def select(ssl_p, out_pp, outlen_p, in_p, in_len, arg, offered=offered):
                    try:
                        data = ctypes.string_at(in_p, in_len)

                        for wanted in offered:
                            target = wanted.encode("ascii")
                            i = 0
                            while i < len(data):
                                length = data[i]
                                proto = data[i + 1:i + 1 + length]
                                if proto == target:
                                    out_pp[0] = ctypes.cast(ctypes.c_void_p(in_p + i + 1), VOID_P)
                                    outlen_p[0] = length
                                    return SSL_TLSEXT_ERR_OK
                                i += 1 + length

                        return SSL_TLSEXT_ERR_NOACK

                    except BaseException:
                        return SSL_TLSEXT_ERR_NOACK

                cb = CB_ALPN_SELECT(select)
                keepalive.append(cb)
                ssl.SSL_CTX_set_alpn_select_cb(ctx, ctypes.cast(cb, VOID_P), None)

        if groups and hasattr(ssl, "SSL_CTX_set1_groups_list"):
            spec = ":".join(g.value for g in groups).encode("ascii")
            if ssl.SSL_CTX_set1_groups_list(ctx, spec) != 1:
                ssl.SSL_CTX_free(ctx)
                raise TLSError(f"SSL_CTX_set1_groups_list failed: {self.errors()}")

        tls13 = [c for c in ciphers if c.value.startswith("TLS_")]
        tls12 = [c for c in ciphers if not c.value.startswith("TLS_")]
        if tls13 and hasattr(ssl, "SSL_CTX_set_ciphersuites"):
            spec = ":".join(c.value for c in tls13).encode("ascii")
            ssl.SSL_CTX_set_ciphersuites(ctx, spec)
        if tls12:
            spec = ":".join(c.value for c in tls12).encode("ascii")
            ssl.SSL_CTX_set_cipher_list(ctx, spec)

        return ctx, keepalive

    def apply_server_config(self, ctx: int, config: TLSServerConfig):
        ssl = self.ssl

        if config.certfile and config.keyfile:
            if ssl.SSL_CTX_use_certificate_chain_file(ctx, config.certfile.encode()) != 1:
                ssl.SSL_CTX_free(ctx)
                raise TLSError(f"failed to load certificate {config.certfile!r}: {self.errors()}")

            if ssl.SSL_CTX_use_PrivateKey_file(ctx, config.keyfile.encode(), SSL_FILETYPE_PEM) != 1:
                ssl.SSL_CTX_free(ctx)
                raise TLSError(f"failed to load private key {config.keyfile!r}: {self.errors()}")

        if config.cafile:
            mode = SSL_VERIFY_PEER
            if int(config.verify_mode) >= 2:
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            ssl.SSL_CTX_set_verify(ctx, mode, None)
            ssl.SSL_CTX_load_verify_locations(ctx, config.cafile.encode(), None)

    def apply_client_config(self, ctx: int, config: TLSClientConfig) -> bool:
        ssl = self.ssl
        verify_hostname = False

        if config.verify:
            ssl.SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, None)
            verify_hostname = config.check_hostname
            if config.cafile or config.capath:
                ssl.SSL_CTX_load_verify_locations(
                    ctx,
                    config.cafile.encode() if config.cafile else None,
                    config.capath.encode() if config.capath else None,
                )
            else:
                ssl.SSL_CTX_set_default_verify_paths(ctx)
        else:
            ssl.SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, None)

        if config.certfile and config.keyfile:
            if ssl.SSL_CTX_use_certificate_chain_file(ctx, config.certfile.encode()) != 1:
                ssl.SSL_CTX_free(ctx)
                raise TLSError(f"failed to load client certificate {config.certfile!r}: {self.errors()}")

            if ssl.SSL_CTX_use_PrivateKey_file(ctx, config.keyfile.encode(), SSL_FILETYPE_PEM) != 1:
                ssl.SSL_CTX_free(ctx)
                raise TLSError(f"failed to load client private key {config.keyfile!r}: {self.errors()}")

        return verify_hostname

    def tls_info(self, ssl_ptr: int) -> TLSInfo:
        version_raw = self.ssl.SSL_get_version(ssl_ptr)
        version = VERSION_MAP.get(version_raw.decode("ascii", "replace") if version_raw else "")

        name = self.cipher_name(ssl_ptr)
        cipher = CIPHER_MAP.get(name) if name else None

        gname = self.group_name(ssl_ptr)
        group = GROUP_MAP.get(gname) if gname else None

        return TLSInfo(version=version, cipher=cipher, group=group)

    def selected_alpn(self, ssl_ptr: int) -> str | None:
        data = VOID_P()
        length = ctypes.c_uint()

        self.ssl.SSL_get0_alpn_selected(ssl_ptr, ctypes.byref(data), ctypes.byref(length))

        if not data.value or not length.value:
            return None

        return ctypes.string_at(data, length.value).decode("ascii", "replace")

    def cipher_name(self, ssl_ptr: int) -> str | None:
        cipher = self.ssl.SSL_get_current_cipher(ssl_ptr)

        if not cipher:
            return None

        name = self.ssl.SSL_CIPHER_get_name(cipher)

        return name.decode("ascii", "replace") if name else None

    def group_name(self, ssl_ptr: int) -> str | None:
        if not hasattr(self.ssl, "SSL_get0_group_name"):
            return None

        name = self.ssl.SSL_get0_group_name(ssl_ptr)

        return name.decode("ascii", "replace") if name else None

    def enable_early_data(self, ctx: int) -> None:
        if hasattr(self.ssl, "SSL_CTX_set_max_early_data"):
            self.ssl.SSL_CTX_set_max_early_data(ctx, 0xffffffff)

        if hasattr(self.ssl, "SSL_CTX_set_recv_max_early_data"):
            self.ssl.SSL_CTX_set_recv_max_early_data(ctx, 0xffffffff)

        self.ssl.SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, SSL_OP_NO_ANTI_REPLAY, None)

    def enable_quic_early_data(self, ssl_ptr: int) -> None:
        if hasattr(self.ssl, "SSL_set_quic_tls_early_data_enabled"):
            self.ssl.SSL_set_quic_tls_early_data_enabled(ssl_ptr, 1)

    def enable_client_sessions(self, ctx: int) -> None:
        self.ssl.SSL_CTX_ctrl(
            ctx, SSL_CTRL_SET_SESS_CACHE_MODE,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_AUTO_CLEAR, None,
        )

    def serialize_session(self, ssl_ptr: int) -> bytes | None:
        ssl = self.ssl
        sess = ssl.SSL_get1_session(ssl_ptr)

        if not sess:
            return None

        try:
            length = ssl.i2d_SSL_SESSION(sess, None)
            if length <= 0:
                return None

            buf_p = VOID_P(None)

            length2 = ssl.i2d_SSL_SESSION(sess, ctypes.byref(buf_p))
            if length2 <= 0 or not buf_p.value:
                return None

            try:
                return bytes(ctypes.string_at(buf_p.value, length2))
            finally:
                if hasattr(self.crypto, "OPENSSL_free") and buf_p.value:
                    self.crypto.OPENSSL_free(buf_p)

        finally:
            ssl.SSL_SESSION_free(sess)

    def deserialize_and_set_session(self, ssl_ptr: int, data: bytes) -> bool:
        ssl = self.ssl
        raw = ctypes.create_string_buffer(data, len(data))
        buf_p = ctypes.cast(raw, VOID_P)
        sess = ssl.d2i_SSL_SESSION(None, ctypes.byref(buf_p), len(data))

        if not sess:
            return False

        try:
            return bool(ssl.SSL_set_session(ssl_ptr, sess))
        finally:
            ssl.SSL_SESSION_free(sess)

def alpn_wire(protocols: tuple[str, ...]) -> bytes:
    out = bytearray()
    for proto in protocols:
        encoded = proto.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    return bytes(out)
