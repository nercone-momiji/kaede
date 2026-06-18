"""
RFC 6455 (WebSocket) conformance tests.
"""
from __future__ import annotations

import struct
import base64
import pytest

from kaede.websocket import (
    build_frame,
    parse_frames,
    compute_accept,
    check_accept,
    generate_key,
    Opcode,
    WebSocket,
    PerMessageDeflate,
    WebSocketProtocolError,
)

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------------------
# RFC 6455 §4.1: Opening handshake – Sec-WebSocket-Accept
# ---------------------------------------------------------------------------

class TestHandshake:
    def test_compute_accept_rfc_example(self):
        """RFC 6455 §1.3: the accept key derivation test vector from the spec"""
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        assert compute_accept(key) == expected

    def test_check_accept_valid(self):
        key = generate_key()
        assert check_accept(key, compute_accept(key)) is True

    def test_check_accept_wrong_accept(self):
        assert check_accept("somekey", "wrongaccept") is False

    def test_check_accept_strips_whitespace(self):
        key = generate_key()
        assert check_accept(key, "  " + compute_accept(key) + "  ") is True

    def test_generate_key_is_16_bytes(self):
        """RFC 6455 §4.1: Sec-WebSocket-Key must be 16-byte random value, base64-encoded"""
        key = generate_key()
        decoded = base64.b64decode(key)
        assert len(decoded) == 16

    def test_guid_used_in_accept(self):
        """RFC 6455 §1.3: GUID '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' must be concatenated"""
        import hashlib
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected_sha1 = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        assert compute_accept(key) == expected_sha1


# ---------------------------------------------------------------------------
# RFC 6455 §5.2: Frame format
# ---------------------------------------------------------------------------

class TestFrameBuilding:
    def test_small_payload_header(self):
        """RFC 6455 §5.2: length 0–125 uses 7-bit length field"""
        frame = build_frame(Opcode.TEXT, b"hello")
        assert frame[0] == 0x81  # FIN=1, opcode=TEXT
        assert frame[1] == 5     # MASK=0, length=5

    def test_medium_payload_uses_16bit_length(self):
        """RFC 6455 §5.2: length 126–65535 uses 16-bit extended length"""
        payload = b"x" * 200
        frame = build_frame(Opcode.BINARY, payload)
        assert (frame[1] & 0x7F) == 126
        length = struct.unpack(">H", frame[2:4])[0]
        assert length == 200

    def test_large_payload_uses_64bit_length(self):
        """RFC 6455 §5.2: length >65535 uses 64-bit extended length"""
        payload = b"x" * 70000
        frame = build_frame(Opcode.BINARY, payload)
        assert (frame[1] & 0x7F) == 127
        length = struct.unpack(">Q", frame[2:10])[0]
        assert length == 70000

    def test_fin_bit_set_by_default(self):
        """RFC 6455 §5.2: FIN bit indicates last fragment"""
        frame = build_frame(Opcode.TEXT, b"x", fin=True)
        assert frame[0] & 0x80

    def test_fin_bit_clear(self):
        frame = build_frame(Opcode.CONTINUATION, b"x", fin=False)
        assert not (frame[0] & 0x80)

    def test_mask_bit_and_key_present(self):
        """RFC 6455 §5.3: client frames MUST be masked"""
        frame = build_frame(Opcode.TEXT, b"hello", mask=True)
        assert frame[1] & 0x80       # MASK bit set
        assert len(frame) == 2 + 4 + 5  # header + 4-byte mask key + payload

    def test_mask_correctly_xors_payload(self):
        payload = b"hello"
        frame = build_frame(Opcode.TEXT, payload, mask=True)
        mask_key = frame[2:6]
        masked_payload = frame[6:]
        unmasked = bytes(masked_payload[i] ^ mask_key[i % 4] for i in range(len(masked_payload)))
        assert unmasked == payload

    def test_rsv1_bit(self):
        frame = build_frame(Opcode.TEXT, b"x", rsv1=True)
        assert frame[0] & 0x40

    def test_rsv1_not_set_by_default(self):
        frame = build_frame(Opcode.TEXT, b"x")
        assert not (frame[0] & 0x40)

    def test_opcode_in_lower_nibble(self):
        frame = build_frame(Opcode.BINARY, b"x")
        assert (frame[0] & 0x0F) == Opcode.BINARY


# ---------------------------------------------------------------------------
# RFC 6455 §5.2: Frame parsing
# ---------------------------------------------------------------------------

class TestFrameParsing:
    def test_parse_unmasked_text(self):
        buf = bytearray(build_frame(Opcode.TEXT, b"hello"))
        frames = parse_frames(buf)
        assert len(frames) == 1
        f = frames[0]
        assert f.opcode == Opcode.TEXT
        assert f.payload == b"hello"
        assert f.fin is True
        assert f.masked is False

    def test_parse_masked_frame(self):
        buf = bytearray(build_frame(Opcode.BINARY, b"data", mask=True))
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert frames[0].payload == b"data"
        assert frames[0].masked is True

    def test_parse_multiple_frames(self):
        raw = build_frame(Opcode.TEXT, b"one") + build_frame(Opcode.TEXT, b"two")
        buf = bytearray(raw)
        frames = parse_frames(buf)
        assert len(frames) == 2
        assert frames[0].payload == b"one"
        assert frames[1].payload == b"two"

    def test_incomplete_header_returns_empty(self):
        buf = bytearray(b"\x81")  # only 1 byte, need at least 2
        frames = parse_frames(buf)
        assert frames == []

    def test_incomplete_payload_returns_empty(self):
        buf = bytearray(b"\x81\x05hel")  # 3 of 5 payload bytes
        frames = parse_frames(buf)
        assert frames == []

    def test_unknown_opcode_raises_protocol_error(self):
        """RFC 6455 §5.2: opcodes 3-7 and 11-15 are reserved"""
        buf = bytearray(bytes([0x83, 0x00]))  # FIN + opcode 3 (reserved)
        with pytest.raises(WebSocketProtocolError):
            parse_frames(buf)

    def test_extended_16bit_length(self):
        payload = b"x" * 200
        buf = bytearray(build_frame(Opcode.BINARY, payload))
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert frames[0].payload == payload

    def test_extended_64bit_length(self):
        payload = b"y" * 70000
        buf = bytearray(build_frame(Opcode.BINARY, payload))
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert frames[0].payload == payload

    def test_max_payload_size_exceeded_raises(self):
        buf = bytearray(build_frame(Opcode.BINARY, b"x" * 100))
        with pytest.raises(ValueError, match="max message size"):
            parse_frames(buf, max_payload_size=50)

    def test_buffer_consumed_after_parse(self):
        buf = bytearray(build_frame(Opcode.TEXT, b"hello"))
        parse_frames(buf)
        assert len(buf) == 0

    def test_rsv1_detected(self):
        raw = build_frame(Opcode.TEXT, b"x", rsv1=True)
        buf = bytearray(raw)
        frames = parse_frames(buf)
        assert frames[0].rsv1 is True

    def test_rsv2_rsv3_detected(self):
        # Manually build frame with RSV2 set: FIN(0x80)|RSV2(0x20)|TEXT(0x01) = 0xA1
        buf = bytearray([0xA1, 0x02, ord("h"), ord("i")])
        frames = parse_frames(buf)
        assert frames[0].rsv_other is True


# ---------------------------------------------------------------------------
# RFC 6455 §5.x: WebSocket server frame handler
# ---------------------------------------------------------------------------

class MockTransport:
    def __init__(self):
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes):
        self.written.extend(data)

    def close(self):
        self.closed = True


def make_ws(**kwargs) -> tuple[WebSocket, MockTransport]:
    transport = MockTransport()
    ws = WebSocket(transport, **kwargs)
    return ws, transport


def feed(ws: WebSocket, raw: bytes):
    buf = bytearray(raw)
    frames = parse_frames(buf)
    for f in frames:
        ws.feed_frame(f)


def parse_written(transport: MockTransport) -> list:
    buf = bytearray(bytes(transport.written))
    return parse_frames(buf)


class TestPingPong:
    def test_ping_receives_pong(self):
        """RFC 6455 §5.5.3: A Pong frame must be sent in response to a Ping"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.PING, b"ping-data"))
        frames = parse_written(transport)
        assert any(f.opcode == Opcode.PONG for f in frames)

    def test_pong_echoes_ping_payload(self):
        """RFC 6455 §5.5.3: Pong must carry same application data as Ping"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.PING, b"token"))
        frames = parse_written(transport)
        pong = next(f for f in frames if f.opcode == Opcode.PONG)
        assert pong.payload == b"token"

    def test_pong_not_required_for_unsolicited_pong(self):
        """RFC 6455 §5.5.3: Unsolicited Pong frames must be ignored"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.PONG, b""))
        assert not transport.closed
        assert len(transport.written) == 0


class TestControlFrameConstraints:
    def test_ping_payload_over_125_closes_1002(self):
        """RFC 6455 §5.5: Control frames MUST NOT exceed 125 bytes payload"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.PING, b"x" * 126))
        assert transport.closed

    def test_fragmented_ping_closes_1002(self):
        """RFC 6455 §5.5: Control frames MUST NOT be fragmented"""
        ws, transport = make_ws(require_masking=False)
        # FIN=0 on PING: b1 = 0x09 (no FIN, PING)
        buf = bytearray([0x09, 0x00])
        frames = parse_frames(buf)
        for f in frames:
            ws.feed_frame(f)
        assert transport.closed


class TestMasking:
    def test_unmasked_client_frame_closes_1002(self):
        """RFC 6455 §5.1: All frames from client MUST be masked; else server closes with 1002"""
        ws, transport = make_ws(require_masking=True)
        feed(ws, build_frame(Opcode.TEXT, b"hello", mask=False))
        assert transport.closed

    def test_masked_frame_accepted(self):
        ws, transport = make_ws(require_masking=True)
        feed(ws, build_frame(Opcode.TEXT, b"hello", mask=True))
        assert not transport.closed
        msg = ws.queue.get_nowait()
        assert msg == b"hello"


class TestCloseHandshake:
    def test_close_frame_echoed(self):
        """RFC 6455 §5.5.1: Upon receiving Close, server MUST send Close in response"""
        ws, transport = make_ws(require_masking=False)
        close_payload = struct.pack(">H", 1000) + b"Normal"
        feed(ws, build_frame(Opcode.CLOSE, close_payload))
        frames = parse_written(transport)
        assert any(f.opcode == Opcode.CLOSE for f in frames)

    def test_close_echoes_valid_code(self):
        """RFC 6455 §5.5.1: Echo the status code back"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", 1000)))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        assert len(close.payload) >= 2
        assert struct.unpack(">H", close.payload[:2])[0] == 1000

    def test_close_empty_payload_echoed(self):
        """RFC 6455 §5.5.1: Close with no payload – echo with no payload"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, b""))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        assert close.payload == b""

    def test_close_one_byte_payload_causes_1002(self):
        """RFC 6455 §5.5.1: 1-byte Close payload is a protocol error"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, b"\x03"))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        code = struct.unpack(">H", close.payload[:2])[0]
        assert code == 1002

    def test_invalid_close_code_cleared(self):
        """RFC 6455 §7.4.2: Invalid close codes must not be echoed"""
        ws, transport = make_ws(require_masking=False)
        # Code 999 is outside the valid range
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", 999)))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        # payload should be empty (invalid code not echoed)
        assert close.payload == b""


class TestRSVBits:
    def test_rsv2_set_without_extension_closes(self):
        """RFC 6455 §5.2: RSV2/RSV3 must be 0 unless an extension is negotiated"""
        ws, transport = make_ws(require_masking=False)
        # b1 = FIN(0x80) | RSV2(0x20) | TEXT(0x01) = 0xA1
        buf = bytearray([0xA1, 0x02, ord("h"), ord("i")])
        frames = parse_frames(buf)
        for f in frames:
            ws.feed_frame(f)
        assert transport.closed

    def test_rsv1_without_deflate_closes(self):
        """RFC 6455 §5.2: RSV1 must be 0 unless permessage-deflate is negotiated"""
        ws, transport = make_ws(require_masking=False, deflate=None)
        feed(ws, build_frame(Opcode.TEXT, b"x", rsv1=True))
        assert transport.closed


class TestFragmentation:
    def test_fragmented_text_reassembled(self):
        """RFC 6455 §5.4: fragmented message must be reassembled in order"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.TEXT, b"hel", fin=False))
        feed(ws, build_frame(Opcode.CONTINUATION, b"lo", fin=True))
        msg = ws.queue.get_nowait()
        assert msg == b"hello"

    def test_interleaved_control_frame_allowed(self):
        """RFC 6455 §5.5: Control frames may be interleaved with fragmented messages"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.TEXT, b"hel", fin=False))
        feed(ws, build_frame(Opcode.PING, b""))   # control frame mid-fragment
        feed(ws, build_frame(Opcode.CONTINUATION, b"lo", fin=True))
        msg = ws.queue.get_nowait()
        assert msg == b"hello"
        frames = parse_written(transport)
        assert any(f.opcode == Opcode.PONG for f in frames)

    def test_new_data_frame_during_fragmentation_closes(self):
        """RFC 6455 §5.4: Starting a new data frame during an unfragmented sequence is a protocol error"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.TEXT, b"hel", fin=False))
        feed(ws, build_frame(Opcode.BINARY, b"oops", fin=True))  # new data frame before continuation
        assert transport.closed

    def test_continuation_without_start_closes(self):
        """RFC 6455 §5.4: Continuation without prior start frame is a protocol error"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CONTINUATION, b"x", fin=True))
        assert transport.closed


class TestTextEncoding:
    def test_valid_utf8_text_accepted(self):
        """RFC 6455 §8.1: Text frames must contain valid UTF-8"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.TEXT, "héllo".encode("utf-8")))
        assert not transport.closed

    def test_invalid_utf8_closes_1007(self):
        """RFC 6455 §8.1: Invalid UTF-8 MUST close with code 1007"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.TEXT, b"\xff\xfe\xfd"))
        assert transport.closed
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        code = struct.unpack(">H", close.payload[:2])[0]
        assert code == 1007

    def test_binary_frame_allows_arbitrary_bytes(self):
        """RFC 6455 §5.6: Binary frames carry arbitrary byte data"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.BINARY, b"\xff\xfe\x00\x01"))
        assert not transport.closed
        msg = ws.queue.get_nowait()
        assert msg == b"\xff\xfe\x00\x01"


# ---------------------------------------------------------------------------
# RFC 7692: permessage-deflate extension
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# RFC 6455 §7.4.2: Close status code validity
# ---------------------------------------------------------------------------

class TestCloseCodeValidity:
    """RFC 6455 §7.4.2: Reserved/invalid codes must not be echoed"""

    @pytest.mark.parametrize("code", [1004, 1005, 1006])
    def test_reserved_close_codes_not_echoed(self, code):
        """RFC 6455 §7.4.2: codes 1004, 1005, 1006 must never be echoed"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", code)))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        assert close.payload == b""

    @pytest.mark.parametrize("code", [0, 999, 1012, 2999, 5000])
    def test_invalid_close_codes_not_echoed(self, code):
        """RFC 6455 §7.4.2: out-of-range codes must not be echoed"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", code)))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        assert close.payload == b""

    @pytest.mark.parametrize("code", [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011])
    def test_defined_close_codes_echoed(self, code):
        """RFC 6455 §7.4.1: defined close codes must be echoed back"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", code)))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        assert struct.unpack(">H", close.payload[:2])[0] == code

    @pytest.mark.parametrize("code", [3000, 3999, 4000, 4999])
    def test_library_and_app_close_codes_echoed(self, code):
        """RFC 6455 §7.4.2: library (3000-3999) and app (4000-4999) codes are valid"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", code)))
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        assert struct.unpack(">H", close.payload[:2])[0] == code


# ---------------------------------------------------------------------------
# RFC 6455 §5.4: Fragmentation of binary messages
# ---------------------------------------------------------------------------

class TestBinaryFragmentation:
    def test_fragmented_binary_reassembled(self):
        """RFC 6455 §5.4: fragmented binary message must be reassembled in order"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.BINARY, b"\x01\x02", fin=False))
        feed(ws, build_frame(Opcode.CONTINUATION, b"\x03\x04", fin=True))
        msg = ws.queue.get_nowait()
        assert msg == b"\x01\x02\x03\x04"

    def test_fragmented_message_exceeding_max_size_closes_1009(self):
        """RFC 6455 §7.4.1: message exceeding max size during fragmentation → 1009"""
        ws, transport = make_ws(require_masking=False, max_message_size=4)
        feed(ws, build_frame(Opcode.TEXT, b"hel", fin=False))
        feed(ws, build_frame(Opcode.CONTINUATION, b"lo!", fin=True))
        assert transport.closed
        frames = parse_written(transport)
        close = next(f for f in frames if f.opcode == Opcode.CLOSE)
        code = struct.unpack(">H", close.payload[:2])[0]
        assert code == 1009

    def test_binary_frame_utf8_not_validated(self):
        """RFC 6455 §5.6: binary frames carry arbitrary bytes; no UTF-8 check"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.BINARY, b"\x00\xff\xfe\xfd"))
        assert not transport.closed
        msg = ws.queue.get_nowait()
        assert msg == b"\x00\xff\xfe\xfd"


# ---------------------------------------------------------------------------
# RFC 6455 §4.1: Handshake key uniqueness
# ---------------------------------------------------------------------------

class TestHandshakeKeyUniqueness:
    def test_generate_key_unique_each_call(self):
        """RFC 6455 §4.1: each WebSocket key must be freshly generated"""
        keys = {generate_key() for _ in range(20)}
        assert len(keys) == 20

    def test_generate_key_base64_valid(self):
        """RFC 6455 §4.1: Sec-WebSocket-Key must be valid base64"""
        import base64
        key = generate_key()
        decoded = base64.b64decode(key)
        assert len(decoded) == 16


# ---------------------------------------------------------------------------
# RFC 6455 §5.5: Control frame size limit (PONG)
# ---------------------------------------------------------------------------

class TestPongConstraints:
    def test_pong_payload_over_125_closes_1002(self):
        """RFC 6455 §5.5: Control frames MUST NOT exceed 125 bytes payload"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.PONG, b"x" * 126))
        assert transport.closed

    def test_pong_payload_exactly_125_accepted(self):
        """125-byte control frame payload is at the limit and must be accepted"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.PONG, b"x" * 125))
        assert not transport.closed


# ---------------------------------------------------------------------------
# RFC 6455 §5.5.1: Close frame after close (no double-close)
# ---------------------------------------------------------------------------

class TestCloseOnceOnly:
    def test_after_close_transport_is_closed(self):
        """RFC 6455 §5.5.1: transport must be closed after close handshake"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, struct.pack(">H", 1000)))
        assert transport.closed

    def test_queue_ends_after_close(self):
        """RFC 6455: receiving Close must signal end of message stream"""
        ws, transport = make_ws(require_masking=False)
        feed(ws, build_frame(Opcode.CLOSE, b""))
        sentinel = ws.queue.get_nowait()
        assert sentinel is None


class TestPerMessageDeflate:
    def test_compress_decompress_roundtrip(self):
        deflate = PerMessageDeflate()
        data = b"hello world" * 100
        assert deflate.decompress(deflate.compress(data)) == data

    def test_trailing_00_00_ff_ff_stripped(self):
        """RFC 7692 §7.2.1: tail sync bytes MUST be removed before sending"""
        deflate = PerMessageDeflate()
        compressed = deflate.compress(b"test")
        assert not compressed.endswith(b"\x00\x00\xff\xff")

    def test_server_no_context_takeover_independent_messages(self):
        """RFC 7692 §8.1.1: server_no_context_takeover → fresh context per message"""
        deflate = PerMessageDeflate(server_no_context_takeover=True)
        c1 = deflate.compress(b"hello world")
        c2 = deflate.compress(b"hello world")
        assert deflate.decompress(c1) == b"hello world"
        assert deflate.decompress(c2) == b"hello world"

    def test_from_client_offer_basic(self):
        assert PerMessageDeflate.from_client_offer("permessage-deflate") is not None

    def test_from_client_offer_with_window_bits(self):
        result = PerMessageDeflate.from_client_offer(
            "permessage-deflate; server_max_window_bits=12"
        )
        assert result is not None
        assert result.server_max_window_bits == 12

    def test_from_client_offer_window_bits_clamped(self):
        """RFC 7692 §8.1.2: window size must be in [8, 15]"""
        result = PerMessageDeflate.from_client_offer(
            "permessage-deflate; server_max_window_bits=4"
        )
        assert result is not None
        assert 8 <= result.server_max_window_bits <= 15

    def test_from_client_offer_no_match_returns_none(self):
        assert PerMessageDeflate.from_client_offer("x-webkit-deflate-frame") is None

    def test_from_client_offer_multiple_extensions(self):
        result = PerMessageDeflate.from_client_offer(
            "x-other, permessage-deflate; client_no_context_takeover"
        )
        assert result is not None
        assert result.client_no_context_takeover is True

    def test_response_header_contains_extension_name(self):
        deflate = PerMessageDeflate()
        assert "permessage-deflate" in deflate.response_header()

    def test_response_header_includes_server_no_context_takeover(self):
        deflate = PerMessageDeflate(server_no_context_takeover=True)
        assert "server_no_context_takeover" in deflate.response_header()

    def test_rsv1_with_deflate_decompresses(self):
        """RSV1 on a text frame triggers decompression when deflate is negotiated"""
        deflate = PerMessageDeflate(server_no_context_takeover=True)
        ws, transport = make_ws(require_masking=False, deflate=deflate)
        payload = deflate.compress(b"hello world")
        feed(ws, build_frame(Opcode.TEXT, payload, rsv1=True))
        assert not transport.closed
        msg = ws.queue.get_nowait()
        assert msg == b"hello world"
