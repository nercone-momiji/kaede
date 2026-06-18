"""
QUIC stateless reset conformance (RFC 9000 §10.3, §18.2).

A server advertises a stateless_reset_token in its transport parameters; the
client stores it and recognises a Stateless Reset by its trailing 16 bytes,
terminating the connection.
"""
from __future__ import annotations

import os

from kaede.quic.connection import ConnectionTerminated

class TestAdvertisement:
    def test_server_advertises_token(self, quic_pair):
        quic_pair.handshake()
        assert len(quic_pair.server.stateless_reset_token) == 16

    def test_client_stores_peer_token(self, quic_pair):
        quic_pair.handshake()
        assert quic_pair.client.peer_stateless_reset_token == quic_pair.server.stateless_reset_token

    def test_client_does_not_advertise_token(self, quic_pair):
        # RFC 9000 §18.2: a client MUST NOT send stateless_reset_token.
        quic_pair.handshake()
        assert quic_pair.server.peer_stateless_reset_token == b""

class TestDetection:
    def test_reset_terminates_connection(self, quic_pair):
        quic_pair.handshake()
        token = quic_pair.client.peer_stateless_reset_token

        reset = bytes([0x40]) + os.urandom(20) + token  # short-header-shaped + token
        quic_pair.client.receive_datagram(reset, quic_pair.now)

        assert quic_pair.client.terminated
        assert any(isinstance(e, ConnectionTerminated) and e.reason == "stateless reset" for e in quic_pair.client.events())

    def test_non_reset_packet_ignored(self, quic_pair):
        quic_pair.handshake()
        # A short-header-shaped datagram NOT ending in the token is just dropped.
        junk = bytes([0x40]) + os.urandom(40)
        quic_pair.client.receive_datagram(junk, quic_pair.now)
        assert not quic_pair.client.terminated
