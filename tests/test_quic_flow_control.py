"""
QUIC receive-side flow control conformance (RFC 9000 §4).

The connection must (a) enforce the stream and connection data limits it
advertised (FLOW_CONTROL_ERROR == 0x03), and (b) replenish credit by sending
MAX_STREAM_DATA / MAX_DATA as the application consumes data, so the peer is not
stalled at the initial limit. Tested at the connection layer with already
"decrypted" frames; no handshake required.
"""
from __future__ import annotations

import os

from kaede.quic import frame as frames
from kaede.quic.connection import QUICConnection, DEFAULT_MAX_STREAM_DATA, DEFAULT_MAX_DATA
from kaede.quic.crypto import PacketKeys, suite_for, INITIAL_CIPHER, LEVEL_APPLICATION
from kaede.quic.recovery import SentPacket, SPACE_APPLICATION

def make_server_conn() -> QUICConnection:
    # is_client=False => the peer is a client; client-initiated streams (even
    # stream ids) are peer-initiated for this endpoint.
    return QUICConnection(is_client=False, tls=object(), original_dcid=b"\x00" * 8, local_cid=b"\x01" * 8, remote_cid=b"\x02" * 8)

class TestEnforcement:
    def test_stream_limit_exceeded_closes_0x03(self):
        conn = make_server_conn()
        conn.on_stream_frame(frames.Stream(0, 0, b"x" * 16, False))
        conn.on_stream_frame(frames.Stream(0, DEFAULT_MAX_STREAM_DATA, b"x", False))
        assert conn.close_pending is not None
        assert conn.close_pending.error_code == 0x03
        assert conn.close_pending.application is False

    def test_connection_limit_exceeded_closes_0x03(self):
        conn = make_server_conn()
        conn.max_data_local = 100  # within the (larger) per-stream limit
        conn.on_stream_frame(frames.Stream(0, 0, b"x" * 200, False))
        assert conn.close_pending is not None
        assert conn.close_pending.error_code == 0x03

    def test_within_limits_ok(self):
        conn = make_server_conn()
        conn.on_stream_frame(frames.Stream(0, 0, b"hello", False))
        assert conn.close_pending is None

class TestCreditReplenishment:
    def test_stream_credit_extended_after_consuming_half(self):
        conn = make_server_conn()
        window = DEFAULT_MAX_STREAM_DATA
        payload = b"x" * (window // 2 + 1)
        conn.on_stream_frame(frames.Stream(0, 0, payload, False))

        stream = conn.streams[0]
        assert stream.max_stream_data_pending is True
        assert stream.max_stream_data_local == stream.receiver.consumed + window

    def test_no_extension_before_threshold(self):
        conn = make_server_conn()
        conn.on_stream_frame(frames.Stream(0, 0, b"x" * 1024, False))
        assert conn.streams[0].max_stream_data_pending is False

class TestEmission:
    def test_max_data_and_max_stream_data_are_sent_and_retransmitted(self):
        conn = make_server_conn()
        conn.send_keys[LEVEL_APPLICATION] = PacketKeys(os.urandom(32), suite_for(INITIAL_CIPHER))

        stream = conn.ensure_stream(0)
        stream.max_stream_data_pending = True
        stream.max_stream_data_local = 50_000
        conn.max_data_pending = True
        conn.max_data_local = 99_999

        packet, ack_eliciting = conn.build_packet(LEVEL_APPLICATION, 0.0, 1200)
        assert packet is not None
        assert ack_eliciting is True

        recorded = [fr for sp in conn.recovery.spaces[SPACE_APPLICATION].sent.values() for fr in sp.frames]
        assert ("max_data",) in recorded
        assert ("max_stream_data", 0) in recorded
        assert conn.max_data_pending is False
        assert conn.streams[0].max_stream_data_pending is False

        # On loss, the credit grants must be re-marked for retransmission.
        lost = SentPacket(packet_number=0, space=SPACE_APPLICATION, time_sent=0.0, ack_eliciting=True, in_flight=True, sent_bytes=64, frames=[("max_data",), ("max_stream_data", 0)])
        conn.on_lost([lost])
        assert conn.max_data_pending is True
        assert conn.streams[0].max_stream_data_pending is True
