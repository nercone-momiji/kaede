"""
QUIC key update conformance (RFC 9001 §6).

Receivers MUST support key updates. This test wires two connections together at
the 1-RTT layer (shared application secrets), round-trips real protected
short-header packets, and verifies that a peer-initiated key update is detected
via the Key Phase bit, decrypted with the next-generation keys, and answered by
rotating the responder's own send keys — in both directions.
"""
from __future__ import annotations

import os

from kaede.quic.connection import QUICConnection
from kaede.quic.crypto import PacketKeys, suite_for, INITIAL_CIPHER, LEVEL_APPLICATION
from kaede.quic.recovery import SPACE_APPLICATION

# PING (0x01) followed by PADDING so the packet is long enough for the header
# protection sample (16 bytes past the packet number).
PAYLOAD = b"\x01" + b"\x00" * 16

def setup_pair() -> tuple[QUICConnection, QUICConnection]:
    suite = suite_for(INITIAL_CIPHER)
    c2s = os.urandom(32)  # client -> server secret
    s2c = os.urandom(32)  # server -> client secret

    client = QUICConnection(is_client=True, tls=object(), original_dcid=b"\x00" * 8, local_cid=b"C" * 8, remote_cid=b"S" * 8)
    server = QUICConnection(is_client=False, tls=object(), original_dcid=b"\x00" * 8, local_cid=b"S" * 8, remote_cid=b"C" * 8)

    for conn, send_secret, recv_secret in ((client, c2s, s2c), (server, s2c, c2s)):
        conn.send_keys[LEVEL_APPLICATION] = PacketKeys(send_secret, suite)
        conn.recv_keys[LEVEL_APPLICATION] = PacketKeys(recv_secret, suite)
        conn.send_keys_next = conn.send_keys[LEVEL_APPLICATION].next_generation()
        conn.recv_keys_next = conn.recv_keys[LEVEL_APPLICATION].next_generation()
        conn.handshake_confirmed = True

    return client, server

def send_app_packet(sender: QUICConnection, receiver: QUICConnection, now: float = 0.0) -> bool:
    packet = sender.assemble_packet(LEVEL_APPLICATION, SPACE_APPLICATION, PAYLOAD, [], True, now)
    consumed = receiver.receive_short_packet(packet, 0, now)
    return consumed > 0 and not receiver.terminated

def test_baseline_packet_round_trips():
    client, server = setup_pair()
    assert send_app_packet(client, server)
    assert server.recv_key_gen == 0

def test_peer_initiated_key_update_detected_and_answered():
    client, server = setup_pair()
    assert send_app_packet(client, server)

    client.initiate_key_update()
    assert client.send_key_gen == 1

    # The server detects the new Key Phase, decrypts with next-gen keys, and
    # responds by rotating its own send keys (RFC 9001 §6.1).
    assert send_app_packet(client, server)
    assert server.recv_key_gen == 1
    assert server.send_key_gen == 1

def test_update_completes_in_both_directions():
    client, server = setup_pair()
    client.initiate_key_update()
    assert send_app_packet(client, server)  # server advances recv+send to gen 1

    # Server now sends at gen 1; the client must accept it and advance its recv.
    assert send_app_packet(server, client)
    assert client.recv_key_gen == 1
    assert client.send_key_gen == 1  # already advanced when it initiated

def test_old_generation_packet_still_decrypts_after_update():
    client, server = setup_pair()
    # Capture an old-generation (gen 0) packet but deliver it after the update.
    old_packet = client.assemble_packet(LEVEL_APPLICATION, SPACE_APPLICATION, PAYLOAD, [], True, 0.0)

    client.initiate_key_update()
    assert send_app_packet(client, server)  # server moves to gen 1, keeps prev keys

    # The reordered gen-0 packet must still decrypt via the retained prev keys.
    consumed = server.receive_short_packet(old_packet, 0, 0.0)
    assert consumed > 0 and not server.terminated
