"""
RFC 9114 (HTTP/3) and RFC 9000 (QUIC variable-length integer) conformance tests.
"""
from __future__ import annotations

import pytest
from kaede.models import Request, Response, Headers
from kaede.http.h3 import H3, H3_FORBIDDEN_HEADERS, FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS, SETTINGS_QPACK_MAXtable_CAPACITY, SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_ENABLE_CONNECT_PROTOCOL, FORBIDDEN_H2_SETTINGS
from kaede.quic.packet import Buffer, encode_uint_var

# RFC 9000 §16: QUIC Variable-Length Integer Encoding

class TestVarIntEncoding:
    """RFC 9000 §16: 2-bit prefix selects 1/2/4/8-byte encoding"""

    @pytest.mark.parametrize("value,expected_len", [
        (0,           1),
        (63,          1),   # 2^6 - 1, fits in 1 byte
        (64,          2),   # needs 2 bytes
        (16383,       2),   # 2^14 - 1, fits in 2 bytes
        (16384,       4),   # needs 4 bytes
        (1073741823,  4),   # 2^30 - 1, fits in 4 bytes
        (1073741824,  8),   # needs 8 bytes
    ])
    def test_encoding_length(self, value, expected_len):
        assert len(encode_uint_var(value)) == expected_len

    @pytest.mark.parametrize("value", [
        0, 1, 63, 64, 100, 16383, 16384, 65535, 1073741823,
    ])
    def test_roundtrip(self, value):
        encoded = encode_uint_var(value)
        buf = Buffer(encoded)
        assert buf.pull_uint_var() == value

    def test_1byte_prefix_bits(self):
        """1-byte values (0–63) must have 0b00 in the two high bits"""
        for v in [0, 1, 63]:
            encoded = encode_uint_var(v)
            assert (encoded[0] >> 6) == 0

    def test_2byte_prefix_bits(self):
        """2-byte values (64–16383) must have 0b01 in the two high bits"""
        for v in [64, 100, 16383]:
            encoded = encode_uint_var(v)
            assert (encoded[0] >> 6) == 1

    def test_4byte_prefix_bits(self):
        """4-byte values must have 0b10 in the two high bits"""
        for v in [16384, 100000, 1073741823]:
            encoded = encode_uint_var(v)
            assert (encoded[0] >> 6) == 2

    def test_8byte_prefix_bits(self):
        """8-byte values must have 0b11 in the two high bits"""
        encoded = encode_uint_var(1073741824)
        assert (encoded[0] >> 6) == 3

    def test_buffer_eof_after_read(self):
        encoded = encode_uint_var(42)
        buf = Buffer(encoded)
        buf.pull_uint_var()
        assert buf.eof()

# RFC 9114 §7: HTTP/3 Frame Format

class TestH3FrameFormat:
    def test_encode_frame_type_and_length(self):
        """RFC 9114 §7.1: HTTP/3 frames are Type + Length + Value"""
        payload = b"hello"
        frame = H3.encode_frame(FRAME_DATA, payload)
        buf = Buffer(frame)
        assert buf.pull_uint_var() == FRAME_DATA
        assert buf.pull_uint_var() == len(payload)
        assert buf.pull_bytes(len(payload)) == payload

    def test_encode_frame_headers_type(self):
        frame = H3.encode_frame(FRAME_HEADERS, b"x" * 10)
        buf = Buffer(frame)
        assert buf.pull_uint_var() == FRAME_HEADERS

    def test_encode_frame_empty_payload(self):
        frame = H3.encode_frame(FRAME_DATA, b"")
        buf = Buffer(frame)
        buf.pull_uint_var()  # type
        assert buf.pull_uint_var() == 0  # zero length

    def test_encode_settings_is_settings_frame(self):
        """RFC 9114 §7.2.4: SETTINGS frame must be first on the control stream"""
        settings = H3.encode_settings()
        buf = Buffer(settings)
        assert buf.pull_uint_var() == FRAME_SETTINGS

# RFC 9114 §7.2.4.1: SETTINGS – forbidden HTTP/2 settings

class TestH3Settings:
    def test_no_forbidden_h2_settings(self):
        """RFC 9114 §7.2.4.1: HTTP/2 SETTINGS identifiers 0x02–0x05 MUST NOT be used"""
        settings_frame = H3.encode_settings()
        buf = Buffer(settings_frame)
        buf.pull_uint_var()  # frame type
        length = buf.pull_uint_var()
        payload = buf.pull_bytes(length)

        pbuf = Buffer(payload)
        while not pbuf.eof():
            ident = pbuf.pull_uint_var()
            pbuf.pull_uint_var()  # value
            assert ident not in FORBIDDEN_H2_SETTINGS, (
                f"Forbidden HTTP/2 setting identifier 0x{ident:02x} found in H3 SETTINGS"
            )

    def test_qpack_maxtable_capacity_zero(self):
        """RFC 9204 §5: SETTINGS_QPACK_MAXtable_CAPACITY=0 means no dynamic table"""
        settings_frame = H3.encode_settings()
        buf = Buffer(settings_frame)
        buf.pull_uint_var()
        length = buf.pull_uint_var()
        payload = buf.pull_bytes(length)

        pbuf = Buffer(payload)
        settings: dict[int, int] = {}
        while not pbuf.eof():
            ident = pbuf.pull_uint_var()
            value = pbuf.pull_uint_var()
            settings[ident] = value

        assert settings.get(SETTINGS_QPACK_MAXtable_CAPACITY, 0) == 0

    def test_qpack_blocked_streams_zero(self):
        settings_frame = H3.encode_settings()
        buf = Buffer(settings_frame)
        buf.pull_uint_var()
        length = buf.pull_uint_var()
        payload = buf.pull_bytes(length)

        pbuf = Buffer(payload)
        settings: dict[int, int] = {}
        while not pbuf.eof():
            ident = pbuf.pull_uint_var()
            value = pbuf.pull_uint_var()
            settings[ident] = value

        assert settings.get(SETTINGS_QPACK_BLOCKED_STREAMS, 0) == 0

    def test_enable_connect_protocol_enabled(self):
        """RFC 9220: SETTINGS_ENABLE_CONNECT_PROTOCOL=1 enables WebSocket over HTTP/3"""
        settings_frame = H3.encode_settings()
        buf = Buffer(settings_frame)
        buf.pull_uint_var()
        length = buf.pull_uint_var()
        payload = buf.pull_bytes(length)

        pbuf = Buffer(payload)
        settings: dict[int, int] = {}
        while not pbuf.eof():
            ident = pbuf.pull_uint_var()
            value = pbuf.pull_uint_var()
            settings[ident] = value

        assert settings.get(SETTINGS_ENABLE_CONNECT_PROTOCOL) == 1

# RFC 9114 §4.2: HTTP/3 response headers

class TestH3ResponseHeaders:
    def test_status_pseudo_header_first(self):
        """RFC 9114 §4.3.1: :status must be present and is the only response pseudo-header"""
        response = Response(status_code=200)
        built = H3.build_response_headers(response)
        assert built[0] == (b":status", b"200")

    @pytest.mark.parametrize("code", [100, 200, 204, 301, 400, 404, 500])
    def test_status_code_as_ascii_bytes(self, code):
        response = Response(status_code=code)
        built = H3.build_response_headers(response)
        assert built[0] == (b":status", str(code).encode("ascii"))

    def test_header_names_are_bytes(self):
        response = Response(status_code=200, headers=Headers({"Content-Type": "text/html"}))
        built = H3.build_response_headers(response)
        assert all(isinstance(n, bytes) for n, v in built)

    def test_header_values_are_bytes(self):
        response = Response(status_code=200, headers=Headers({"Content-Type": "text/html"}))
        built = H3.build_response_headers(response)
        assert all(isinstance(v, bytes) for n, v in built)

    @pytest.mark.parametrize("header", H3_FORBIDDEN_HEADERS)
    def test_forbidden_headers_stripped(self, header):
        """RFC 9114 §4.2: connection-specific headers MUST NOT be sent"""
        response = Response(status_code=200, headers=Headers({header: "value"}))
        built = H3.build_response_headers(response)
        names = [n for n, v in built]
        assert header.encode() not in names

    def test_crlf_in_name_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Evil\r\n": "val"}))
        built = H3.build_response_headers(response)
        names = [n for n, v in built]
        assert not any(b"\r" in n or b"\n" in n for n in names)

    def test_crlf_in_value_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Test": "val\r\nInj: x"}))
        built = H3.build_response_headers(response)
        values = [v for n, v in built]
        assert not any(b"\r" in v or b"\n" in v for v in values)

    def test_null_in_header_filtered(self):
        response = Response(status_code=200, headers=Headers({"X-Test": "val\x00ue"}))
        built = H3.build_response_headers(response)
        values = [v for n, v in built]
        assert not any(b"\x00" in v for v in values)

# RFC 9114 §4.3: HTTP/3 request headers

class TestH3RequestHeaders:
    def test_method_pseudo(self):
        req = Request(method="POST", target="/", scheme="https", headers=Headers({}))
        built = H3.build_request_headers(req, "example.com")
        assert (b":method", b"POST") in built

    def test_scheme_pseudo(self):
        req = Request(method="GET", target="/", scheme="https", headers=Headers({}))
        built = H3.build_request_headers(req, "example.com")
        assert (b":scheme", b"https") in built

    def test_authority_pseudo(self):
        req = Request(method="GET", target="/", headers=Headers({}))
        built = H3.build_request_headers(req, "example.com:443")
        assert (b":authority", b"example.com:443") in built

    def test_path_pseudo(self):
        req = Request(method="GET", target="/path?q=1", headers=Headers({}))
        built = H3.build_request_headers(req, "example.com")
        assert (b":path", b"/path?q=1") in built

    def test_host_excluded(self):
        """RFC 9114 §4.3.1: :authority replaces Host header"""
        req = Request(method="GET", target="/", headers=Headers({"Host": "example.com"}))
        built = H3.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert b"host" not in names

    @pytest.mark.parametrize("header", H3_FORBIDDEN_HEADERS)
    def test_forbidden_excluded_from_request(self, header):
        req = Request(method="GET", target="/", headers=Headers({header: "value"}))
        built = H3.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert header.encode() not in names

    def test_header_names_are_bytes(self):
        req = Request(method="GET", target="/", headers=Headers({"Accept": "text/html"}))
        built = H3.build_request_headers(req, "example.com")
        assert all(isinstance(n, bytes) for n, v in built)

    def test_header_values_are_bytes(self):
        req = Request(method="GET", target="/", headers=Headers({"Accept": "text/html"}))
        built = H3.build_request_headers(req, "example.com")
        assert all(isinstance(v, bytes) for n, v in built)

    def test_content_length_excluded_from_explicit_headers(self):
        """RFC 9114: content-length in the Headers dict is excluded (not double-counted)"""
        req = Request(method="GET", target="/", headers=Headers({"Content-Length": "0"}))
        built = H3.build_request_headers(req, "example.com")
        names = [n for n, v in built]
        assert b"content-length" not in names

# RFC 9000 §16: Buffer — push operations and state

class TestBufferPush:
    def test_push_uint8_appends_single_byte(self):
        buf = Buffer()
        buf.push_uint8(0xAB)
        assert buf.data == bytes([0xAB])

    def test_push_uint8_masks_to_byte(self):
        buf = Buffer()
        buf.push_uint8(0x1FF)  # only lowest byte used
        assert len(buf) == 1

    def test_push_uint16_big_endian(self):
        buf = Buffer()
        buf.push_uint16(0x0102)
        assert buf.data == b"\x01\x02"

    def test_push_uint32_big_endian(self):
        buf = Buffer()
        buf.push_uint32(0x01020304)
        assert buf.data == b"\x01\x02\x03\x04"

    def test_push_uint64_big_endian(self):
        buf = Buffer()
        buf.push_uint64(0x0102030405060708)
        assert buf.data == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_push_bytes_appends_data(self):
        buf = Buffer()
        buf.push_bytes(b"hello")
        assert buf.data == b"hello"

    def test_push_uint_var_produces_decodeable_value(self):
        """push_uint_var must produce bytes that pull_uint_var can decode."""
        for value in [0, 63, 64, 16383, 16384, 1073741823, 1073741824]:
            buf = Buffer()
            buf.push_uint_var(value)
            reader = Buffer(buf.data)
            assert reader.pull_uint_var() == value

    def test_push_and_pull_roundtrip_uint8(self):
        buf = Buffer()
        buf.push_uint8(0xFF)
        reader = Buffer(buf.data)
        assert reader.pull_uint8() == 0xFF

    def test_push_and_pull_roundtrip_uint16(self):
        buf = Buffer()
        buf.push_uint16(0xBEEF)
        reader = Buffer(buf.data)
        assert reader.pull_uint16() == 0xBEEF

    def test_push_and_pull_roundtrip_uint32(self):
        buf = Buffer()
        buf.push_uint32(0xDEADBEEF)
        reader = Buffer(buf.data)
        assert reader.pull_uint32() == 0xDEADBEEF

    def test_push_and_pull_roundtrip_uint64(self):
        buf = Buffer()
        buf.push_uint64(0xCAFEBABEDEADBEEF)
        reader = Buffer(buf.data)
        assert reader.pull_uint64() == 0xCAFEBABEDEADBEEF

    def test_sequential_pushes_appended_in_order(self):
        buf = Buffer()
        buf.push_uint8(0x01)
        buf.push_uint8(0x02)
        buf.push_uint8(0x03)
        assert buf.data == b"\x01\x02\x03"

class TestBufferState:
    def test_tell_at_zero_initially(self):
        buf = Buffer(b"hello")
        assert buf.tell() == 0

    def test_tell_advances_after_pull(self):
        buf = Buffer(b"hello")
        buf.pull_uint8()
        assert buf.tell() == 1

    def test_seek_changes_position(self):
        buf = Buffer(b"hello")
        buf.seek(3)
        assert buf.tell() == 3

    def test_remaining_decreases_on_read(self):
        buf = Buffer(b"hello")
        assert buf.remaining() == 5
        buf.pull_uint8()
        assert buf.remaining() == 4

    def test_eof_false_with_data(self):
        buf = Buffer(b"x")
        assert buf.eof() is False

    def test_eof_true_after_exhausted(self):
        buf = Buffer(b"x")
        buf.pull_uint8()
        assert buf.eof() is True

    def test_eof_true_on_empty_buffer(self):
        buf = Buffer(b"")
        assert buf.eof() is True

    def test_len_returns_total_data_length(self):
        buf = Buffer(b"hello")
        assert len(buf) == 5

    def test_len_unaffected_by_read_position(self):
        """len() returns the total buffer size, not remaining bytes."""
        buf = Buffer(b"hello")
        buf.pull_uint8()
        assert len(buf) == 5  # still 5, pos just moved

    def test_data_returns_all_bytes(self):
        raw = b"\x01\x02\x03"
        buf = Buffer(raw)
        assert buf.data == raw

    def test_pull_bytes_past_end_raises_buffer_error(self):
        """Reading beyond the buffer end must raise BufferError (a ValueError subclass)."""
        from kaede.quic.packet import BufferError
        buf = Buffer(b"hi")
        with pytest.raises(BufferError):
            buf.pull_bytes(10)

    def test_pull_uint8_past_end_raises_buffer_error(self):
        from kaede.quic.packet import BufferError
        buf = Buffer(b"")
        with pytest.raises(BufferError):
            buf.pull_uint8()

    def test_pull_uint16_past_end_raises_buffer_error(self):
        from kaede.quic.packet import BufferError
        buf = Buffer(b"\x01")  # only 1 byte, needs 2
        with pytest.raises(BufferError):
            buf.pull_uint16()

class TestEncodeUintVarEdgeCases:
    def test_negative_value_raises_value_error(self):
        """RFC 9000 §16: Variable-length integers are non-negative."""
        with pytest.raises(ValueError):
            encode_uint_var(-1)

    def test_max_value_is_accepted(self):
        """RFC 9000 §16: Maximum QUIC varint is 2^62 − 1."""
        max_val = 0x3FFFFFFFFFFFFFFF  # 2^62 - 1
        encoded = encode_uint_var(max_val)
        assert len(encoded) == 8
        buf = Buffer(encoded)
        assert buf.pull_uint_var() == max_val

    def test_too_large_raises_value_error(self):
        """Values >= 2^62 cannot be encoded."""
        with pytest.raises(ValueError):
            encode_uint_var(0x4000000000000000)

    def test_zero_encoded_in_one_byte(self):
        assert encode_uint_var(0) == b"\x00"

    def test_boundary_63_is_one_byte(self):
        assert len(encode_uint_var(63)) == 1

    def test_boundary_64_is_two_bytes(self):
        assert len(encode_uint_var(64)) == 2

    def test_boundary_16383_is_two_bytes(self):
        assert len(encode_uint_var(16383)) == 2

    def test_boundary_16384_is_four_bytes(self):
        assert len(encode_uint_var(16384)) == 4

    def test_boundary_1073741823_is_four_bytes(self):
        assert len(encode_uint_var(1073741823)) == 4

    def test_boundary_1073741824_is_eight_bytes(self):
        assert len(encode_uint_var(1073741824)) == 8
