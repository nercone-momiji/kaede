"""
QUIC idle timeout and draining-state conformance (RFC 9000 §10.1, §10.2).
"""
from __future__ import annotations

from kaede.quic.connection import QUICConnection, ConnectionTerminated

def make_conn() -> QUICConnection:
    return QUICConnection(is_client=True, tls=object(), original_dcid=b"\x00" * 8, local_cid=b"C" * 8, remote_cid=b"S" * 8)

class TestEffectiveTimeout:
    def test_min_of_both(self):
        conn = make_conn()
        conn.local_max_idle = 30000
        conn.peer_max_idle = 10000
        assert conn.effective_idle_timeout() == 10.0

    def test_disabled_when_both_zero(self):
        conn = make_conn()
        conn.local_max_idle = 0
        conn.peer_max_idle = 0
        assert conn.effective_idle_timeout() is None
        assert conn.idle_deadline() is None

class TestTermination:
    def test_terminates_after_deadline(self):
        conn = make_conn()
        conn.peer_max_idle = 10000  # 10s, below the 30s local default
        conn.idle_base = 0.0

        conn.handle_timer(1.0)
        assert not conn.terminated

        conn.handle_timer(100.0)
        assert conn.terminated
        assert any(isinstance(e, ConnectionTerminated) for e in conn.events())

    def test_get_timer_includes_idle_deadline(self):
        conn = make_conn()
        conn.peer_max_idle = 5000
        conn.idle_base = 0.0
        timer = conn.get_timer()
        assert timer is not None and timer >= 5.0

    def test_no_termination_when_disabled(self):
        conn = make_conn()
        conn.local_max_idle = 0
        conn.peer_max_idle = 0
        conn.idle_base = 0.0
        conn.handle_timer(1_000_000.0)
        assert not conn.terminated

class TestDraining:
    def test_draining_sends_nothing(self):
        # Peer-initiated close / idle timeout: terminated with no close to emit.
        conn = make_conn()
        conn.terminated = True
        assert conn.datagrams_to_send(0.0) == []
