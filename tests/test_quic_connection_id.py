"""
QUIC connection ID management conformance (RFC 9000 §5.1, §19.15, §19.16).

The endpoint issues spare connection IDs up to the peer's
active_connection_id_limit, maintains the peer's CID pool, honors
retire_prior_to, and enforces its own limit.
"""
from __future__ import annotations

from kaede.quic.frame import NewConnectionId

class TestIssuance:
    def test_both_issue_extra_cid(self, quic_pair):
        quic_pair.handshake()
        assert quic_pair.client.next_cid_seq >= 2  # seq 0 (handshake) + >=1 issued
        assert quic_pair.server.next_cid_seq >= 2

    def test_peer_cid_pools_populated(self, quic_pair):
        quic_pair.handshake()
        assert len(quic_pair.client.peer_cids) >= 2
        assert len(quic_pair.server.peer_cids) >= 2

class TestRetirePriorTo:
    def test_retire_prior_to_switches_active_cid(self, quic_pair):
        quic_pair.handshake()
        client = quic_pair.client

        client.on_new_connection_id(NewConnectionId(5, 5, b"NEWCID01", b"\x00" * 16))

        assert client.remote_cid == b"NEWCID01"
        assert client.remote_cid_seq == 5
        assert client.retire_cids_pending  # earlier CIDs queued for retirement

class TestLimitEnforcement:
    def test_exceeding_active_limit_closes_0x09(self, quic_pair):
        quic_pair.handshake()
        client = quic_pair.client
        # Pool already holds seq 0 and 1 (limit 2); a third without retirement
        # is a CONNECTION_ID_LIMIT_ERROR.
        client.on_new_connection_id(NewConnectionId(2, 0, b"EXTRACID", b"\x00" * 16))
        assert client.close_pending is not None
        assert client.close_pending.error_code == 0x09

    def test_retire_prior_to_above_sequence_is_error(self, quic_pair):
        quic_pair.handshake()
        client = quic_pair.client
        client.on_new_connection_id(NewConnectionId(3, 5, b"BADCID00", b"\x00" * 16))
        assert client.close_pending is not None
        assert client.close_pending.error_code == 0x07
