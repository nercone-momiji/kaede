"""
HTTP/1.1 message parsing conformance for two MUST-level rules that are also
request-smuggling vectors:

- RFC 9110 §5.5: CR/LF/NUL (and other controls) in a field value must be
  rejected (Kaede rejects rather than replaces).
- RFC 9112 §7.1.1: chunk-size = 1*HEXDIG; non-hex forms must be rejected.
"""
from __future__ import annotations

import ipaddress

import pytest

from kaede.http.h1 import H1

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)

def parse(raw: bytes):
    return H1.parse_request(raw, client=CLIENT)

class TestFieldValueControls:
    def test_nul_in_value_rejected(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: ab\x00cd\r\n\r\n"
        with pytest.raises(ValueError):
            parse(raw)

    def test_other_control_rejected(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\x07b\r\n\r\n"
        with pytest.raises(ValueError):
            parse(raw)

    def test_htab_and_obs_text_allowed(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\tb\xc3\xa9\r\n\r\n"
        request = parse(raw)
        assert request.headers.get("X-Test") == "a\tb\xc3\xa9"

class TestChunkSize:
    def test_valid_chunk(self):
        assert H1.decode_chunked(b"5\r\nhello\r\n0\r\n\r\n") == b"hello"

    def test_chunk_ext_ignored(self):
        assert H1.decode_chunked(b"5;name=value\r\nhello\r\n0\r\n\r\n") == b"hello"

    @pytest.mark.parametrize("size", [b"0x5", b"1_a", b"+5", b" 5", b"-5", b""])
    def test_non_hexdig_chunk_size_rejected(self, size):
        raw = size + b"\r\nhello\r\n0\r\n\r\n"
        with pytest.raises(ValueError):
            H1.decode_chunked(raw)

    def test_uppercase_hex_accepted(self):
        # 0xA bytes of data.
        assert H1.decode_chunked(b"A\r\n0123456789\r\n0\r\n\r\n") == b"0123456789"
