from __future__ import annotations

import os
from dataclasses import dataclass

from . import frame as frames
from . import packet
from .packet import Buffer, encode_uint_var
from .crypto import PacketKeys, suite_for, initial_keys, verify_retry_integrity_tag, LEVEL_INITIAL, LEVEL_HANDSHAKE, LEVEL_APPLICATION, INITIAL_CIPHER
from .stream import Stream, StreamSender, StreamReceiver, stream_is_bidirectional, stream_is_client_initiated
from .recovery import Recovery, SentPacket, Space, level_to_space, SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_APPLICATION
from .tls import QuicTLS

MAX_DATAGRAM_SIZE = 1350
INITIAL_DATAGRAM_MIN = 1200
AEAD_TAG = 16

TP_ORIGINAL_DCID = 0x00
TP_MAX_IDLE_TIMEOUT = 0x01
TP_STATELESS_RESET_TOKEN = 0x02
TP_MAX_UDP_PAYLOAD = 0x03
TP_INITIAL_MAX_DATA = 0x04
TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05
TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06
TP_INITIAL_MAX_STREAM_DATA_UNI = 0x07
TP_INITIAL_MAX_STREAMS_BIDI = 0x08
TP_INITIAL_MAX_STREAMS_UNI = 0x09
TP_ACK_DELAY_EXPONENT = 0x0A
TP_MAX_ACK_DELAY = 0x0B
TP_ACTIVE_CONNECTION_ID_LIMIT = 0x0E
TP_INITIAL_SCID = 0x0F
TP_MAX_DATAGRAM_FRAME_SIZE = 0x20  # RFC 9221

DEFAULT_MAX_DATAGRAM_FRAME_SIZE = 65535

DEFAULT_MAX_DATA = 1 << 24
DEFAULT_MAX_STREAM_DATA = 1 << 20
DEFAULT_MAX_STREAMS = 128

@dataclass
class HandshakeCompleted:
    alpn: str | None

@dataclass
class StreamDataReceived:
    stream_id: int
    data: bytes
    end_stream: bool

@dataclass
class StreamReset:
    stream_id: int
    error_code: int

@dataclass
class StopSendingReceived:
    stream_id: int
    error_code: int

@dataclass
class ConnectionTerminated:
    error_code: int
    reason: str

@dataclass
class DatagramReceived:
    data: bytes

def encode_transport_parameters(params: dict[int, int | bytes]) -> bytes:
    buf = bytearray()
    for tp_id, value in params.items():
        buf += encode_uint_var(tp_id)
        if isinstance(value, (bytes, bytearray)):
            buf += encode_uint_var(len(value))
            buf += value
        else:
            encoded = encode_uint_var(value)
            buf += encode_uint_var(len(encoded))
            buf += encoded
    return bytes(buf)

def decode_transport_parameters(data: bytes) -> dict[int, int | bytes]:
    out: dict[int, int | bytes] = {}
    buf = Buffer(data)
    while not buf.eof():
        tp_id = buf.pull_uint_var()
        length = buf.pull_uint_var()
        raw = buf.pull_bytes(length)
        if tp_id in (TP_ORIGINAL_DCID, TP_INITIAL_SCID, TP_STATELESS_RESET_TOKEN):
            out[tp_id] = raw
        else:
            try:
                out[tp_id] = Buffer(raw).pull_uint_var() if raw else 0
            except Exception:
                out[tp_id] = raw
    return out

class QUICConnection:
    def __init__(self, *, is_client: bool, tls: QuicTLS, original_dcid: bytes, local_cid: bytes, remote_cid: bytes, peer_completed_cb=None):
        self.is_client = is_client
        self.tls = tls
        self.original_dcid = original_dcid
        self.local_cid = local_cid
        self.remote_cid = remote_cid

        self.handshake_complete = False
        self.handshake_confirmed = False
        self.handshake_done_pending = False
        self.terminated = False
        self.close_pending: frames.ConnectionClose | None = None
        self.close_sent = False

        self.bytes_received: int = 0
        self.bytes_sent_pre_validation: int = 0
        self.data_sent: int = 0

        self.recovery = Recovery(MAX_DATAGRAM_SIZE)

        # Idle timeout (RFC 9000 §10.1). The effective timeout is the minimum of
        # both endpoints' advertised values; the timer restarts on a successfully
        # processed packet and on sending the first ack-eliciting packet since.
        self.local_max_idle = 30000  # milliseconds; mirrors the advertised value
        self.peer_max_idle = 0
        self.idle_base: float | None = None
        self.ack_eliciting_since_recv = False

        self.data_blocked_pending: bool = False
        self.streams_blocked_bidi: bool = False
        self.streams_blocked_uni: bool = False
        self._events: list = []

        self.send_keys: dict[int, PacketKeys] = {}
        self.recv_keys: dict[int, PacketKeys] = {}

        # Key update state (RFC 9001 §6). Send and receive key generations are
        # tracked independently so updates initiated by either endpoint are
        # handled; the Key Phase bit transmitted/expected is generation & 1.
        # *_next hold precomputed next-generation keys; recv_keys_prev retains
        # the prior generation to decrypt reordered packets.
        self.send_key_gen = 0
        self.recv_key_gen = 0
        self.send_keys_next: PacketKeys | None = None
        self.recv_keys_next: PacketKeys | None = None
        self.recv_keys_prev: PacketKeys | None = None

        ck, sk = initial_keys(original_dcid)
        if is_client:
            self.send_keys[LEVEL_INITIAL], self.recv_keys[LEVEL_INITIAL] = ck, sk
        else:
            self.send_keys[LEVEL_INITIAL], self.recv_keys[LEVEL_INITIAL] = sk, ck

        self.crypto_send = {LEVEL_INITIAL: StreamSender(), LEVEL_HANDSHAKE: StreamSender(), LEVEL_APPLICATION: StreamSender()}
        self.crypto_recv = {LEVEL_INITIAL: StreamReceiver(), LEVEL_HANDSHAKE: StreamReceiver(), LEVEL_APPLICATION: StreamReceiver()}

        self.next_pn = {SPACE_INITIAL: 0, SPACE_HANDSHAKE: 0, SPACE_APPLICATION: 0}
        self.recv_pns: dict[int, set[int]] = {SPACE_INITIAL: set(), SPACE_HANDSHAKE: set(), SPACE_APPLICATION: set()}
        self.largest_recv: dict[int, int] = {}
        self.largest_recv_time: dict[int, float] = {}
        self.ack_needed = {SPACE_INITIAL: False, SPACE_HANDSHAKE: False, SPACE_APPLICATION: False}

        self.streams: dict[int, Stream] = {}
        self.next_uni = 2 if is_client else 3
        self.next_bidi = 0 if is_client else 1
        self.peer_transport_params: dict[int, int | bytes] = {}
        self.peer_max_data = DEFAULT_MAX_DATA
        self.max_bidi_streams: int | None = None
        self.max_uni_streams: int | None = None
        self.data_sent = 0

        # Receive-side connection flow control (RFC 9000 §4). max_data_local is
        # the connection limit we advertise; it is extended via MAX_DATA frames
        # as the application consumes stream data.
        self.max_data_local = DEFAULT_MAX_DATA
        self.data_received = 0
        self.max_data_pending = False

        # Unreliable datagrams (RFC 9221). We advertise our receive limit; the
        # peer's limit (0 = unsupported) gates what we may send.
        self.local_max_datagram_frame_size = DEFAULT_MAX_DATAGRAM_FRAME_SIZE
        self.peer_max_datagram_frame_size = 0
        self.datagrams_pending: list[bytes] = []

        # Stateless reset (RFC 9000 §10.3). Only a server advertises a token (in
        # transport parameters); the peer stores it to recognise a reset.
        self.stateless_reset_token = b""
        self.peer_stateless_reset_token = b""
        self.suite = suite_for(INITIAL_CIPHER)

        self.remote_cid_set = not is_client
        self.path_response_pending: bytes | None = None
        self.needs_advance = True
        self.buffered_packets: list[bytes] = []

        self.local_bidi_limit = DEFAULT_MAX_STREAMS
        self.local_uni_limit = DEFAULT_MAX_STREAMS

        self.retry_token: bytes = b""

        self._tls_factory = None

    @classmethod
    def create_client(cls, tls_factory, server_name: str, local_tp_extra: dict | None = None) -> "QUICConnection":
        local_cid = os.urandom(8)
        original_dcid = os.urandom(8)
        tp = {
            TP_INITIAL_MAX_DATA: DEFAULT_MAX_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAM_DATA_UNI: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAMS_BIDI: DEFAULT_MAX_STREAMS,
            TP_INITIAL_MAX_STREAMS_UNI: DEFAULT_MAX_STREAMS,
            TP_ACTIVE_CONNECTION_ID_LIMIT: 2,
            TP_INITIAL_SCID: local_cid,
            TP_MAX_IDLE_TIMEOUT: 30000,
            TP_MAX_UDP_PAYLOAD: MAX_DATAGRAM_SIZE,
            TP_MAX_DATAGRAM_FRAME_SIZE: DEFAULT_MAX_DATAGRAM_FRAME_SIZE
        }

        if local_tp_extra:
            tp.update(local_tp_extra)

        tls = tls_factory(encode_transport_parameters(tp))

        conn = cls(is_client=True, tls=tls, original_dcid=original_dcid, local_cid=local_cid, remote_cid=original_dcid)
        conn._tls_factory = tls_factory
        return conn

    @classmethod
    def create_server(cls, first_datagram: bytes, tls_factory, local_tp_extra: dict | None = None) -> "QUICConnection":
        hdr = packet.parse_long_header(first_datagram, 0)

        original_dcid = hdr.destination_cid
        if len(original_dcid) < 8:
            raise ValueError(f"Initial packet DCID too short: {len(original_dcid)} bytes (minimum 8)")

        remote_cid = hdr.source_cid
        local_cid = os.urandom(8)
        reset_token = os.urandom(16)

        tp = {
            TP_ORIGINAL_DCID: original_dcid,
            TP_INITIAL_SCID: local_cid,
            TP_STATELESS_RESET_TOKEN: reset_token,
            TP_INITIAL_MAX_DATA: DEFAULT_MAX_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAM_DATA_UNI: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAMS_BIDI: DEFAULT_MAX_STREAMS,
            TP_INITIAL_MAX_STREAMS_UNI: DEFAULT_MAX_STREAMS,
            TP_ACTIVE_CONNECTION_ID_LIMIT: 2,
            TP_MAX_IDLE_TIMEOUT: 30000,
            TP_MAX_UDP_PAYLOAD: MAX_DATAGRAM_SIZE,
            TP_MAX_DATAGRAM_FRAME_SIZE: DEFAULT_MAX_DATAGRAM_FRAME_SIZE
        }

        if local_tp_extra:
            tp.update(local_tp_extra)

        tls = tls_factory(encode_transport_parameters(tp))

        conn = cls(is_client=False, tls=tls, original_dcid=original_dcid, local_cid=local_cid, remote_cid=remote_cid)
        conn.stateless_reset_token = reset_token
        return conn

    def get_next_available_stream_id(self, is_bidi: bool = True) -> int:
        if is_bidi:
            if self.max_bidi_streams is not None and self.next_bidi // 4 >= self.max_bidi_streams:
                self.streams_blocked_bidi = True
                raise ConnectionError("peer bidirectional stream limit reached")
            sid = self.next_bidi
            self.next_bidi += 4
        else:
            base = 2 if self.is_client else 3
            if self.max_uni_streams is not None and (self.next_uni - base) // 4 >= self.max_uni_streams:
                self.streams_blocked_uni = True
                raise ConnectionError("peer unidirectional stream limit reached")
            sid = self.next_uni
            self.next_uni += 4

        self.ensure_stream(sid)
        return sid

    def ensure_stream(self, stream_id: int) -> Stream:
        stream = self.streams.get(stream_id)

        if stream is None:
            stream = Stream(stream_id)
            stream.max_stream_data_local = DEFAULT_MAX_STREAM_DATA
            stream.max_stream_data_remote = self.peer_initial_stream_limit(stream_id)
            self.streams[stream_id] = stream

        return stream

    def peer_initial_stream_limit(self, stream_id: int) -> int:
        if not stream_is_bidirectional(stream_id):
            return int(self.peer_transport_params.get(TP_INITIAL_MAX_STREAM_DATA_UNI, 0) or 0)

        if stream_is_client_initiated(stream_id) == self.is_client:
            return int(self.peer_transport_params.get(TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0) or 0)

        return int(self.peer_transport_params.get(TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0) or 0)

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False):
        stream = self.ensure_stream(stream_id)
        stream.sender.write(data, end_stream)

    def send_datagram(self, data: bytes):
        # RFC 9221: only after the peer advertised a non-zero limit, and never
        # larger than that limit (frame type + length + payload). DATAGRAM
        # frames cannot be fragmented, so the frame must also fit in one packet.
        if self.peer_max_datagram_frame_size <= 0:
            raise ValueError("peer does not support QUIC DATAGRAM frames")
        frame_size = len(frames.Datagram(data).encode())
        if frame_size > self.peer_max_datagram_frame_size:
            raise ValueError("DATAGRAM frame exceeds peer's max_datagram_frame_size")
        if frame_size > MAX_DATAGRAM_SIZE - 64:
            raise ValueError("DATAGRAM frame too large to fit a single packet")
        self.datagrams_pending.append(data)

    def reset_stream(self, stream_id: int, error_code: int):
        stream = self.ensure_stream(stream_id)
        stream.reset_pending = (error_code, stream.sender.written)

    def close(self, error_code: int = 0, reason: str = "", application: bool = True):
        if self.close_pending is None and not self.terminated:
            self.close_pending = frames.ConnectionClose(error_code, 0, reason.encode(), application)

    def events(self) -> list:
        out = self._events
        self._events = []
        return out

    def install_handshake_keys(self):
        for level in (LEVEL_HANDSHAKE, LEVEL_APPLICATION):
            if level not in self.send_keys:
                ws = self.tls.write_secret(level)
                rs = self.tls.read_secret(level)

                if ws and rs:
                    name = self.tls.cipher_name() or INITIAL_CIPHER
                    self.suite = suite_for(name)
                    self.send_keys[level] = PacketKeys(ws, self.suite)
                    self.recv_keys[level] = PacketKeys(rs, self.suite)

                    if level == LEVEL_APPLICATION:
                        # Precompute the next key generation so a peer-initiated
                        # key update can be processed immediately (RFC 9001 §6).
                        self.send_keys_next = self.send_keys[level].next_generation()
                        self.recv_keys_next = self.recv_keys[level].next_generation()

    def run_handshake(self):
        if self.terminated:
            return
        out = self.tls.advance()
        for level, data in out:
            self.crypto_send[level].write(data)
        self.install_handshake_keys()

        if self.tls.peer_transport_params and not self.peer_transport_params:
            self.peer_transport_params = decode_transport_parameters(self.tls.peer_transport_params)

            if self.is_client:
                peer_odcid = self.peer_transport_params.get(TP_ORIGINAL_DCID)
                if not isinstance(peer_odcid, bytes) or peer_odcid != self.original_dcid:
                    self.close(0x08, "original_destination_connection_id mismatch", application=False)
                    return

            self.peer_max_data = int(self.peer_transport_params.get(TP_INITIAL_MAX_DATA, DEFAULT_MAX_DATA) or 0)
            self.peer_max_idle = int(self.peer_transport_params.get(TP_MAX_IDLE_TIMEOUT, 0) or 0)
            self.peer_max_datagram_frame_size = int(self.peer_transport_params.get(TP_MAX_DATAGRAM_FRAME_SIZE, 0) or 0)

            peer_token = self.peer_transport_params.get(TP_STATELESS_RESET_TOKEN)
            if isinstance(peer_token, (bytes, bytearray)) and len(peer_token) == 16:
                self.peer_stateless_reset_token = bytes(peer_token)
            self.max_bidi_streams = int(self.peer_transport_params.get(TP_INITIAL_MAX_STREAMS_BIDI, DEFAULT_MAX_STREAMS) or DEFAULT_MAX_STREAMS)
            self.max_uni_streams = int(self.peer_transport_params.get(TP_INITIAL_MAX_STREAMS_UNI, DEFAULT_MAX_STREAMS) or DEFAULT_MAX_STREAMS)
            for stream in self.streams.values():
                if stream.max_stream_data_remote == 0:
                    stream.max_stream_data_remote = self.peer_initial_stream_limit(stream.stream_id)

        if self.tls.handshake_complete and not self.handshake_complete:
            self.handshake_complete = True
            if not self.is_client:
                self.handshake_done_pending = True
                self.handshake_confirmed = True

            self._events.append(HandshakeCompleted(self.tls.alpn()))

    def receive_datagram(self, data: bytes, now: float):
        if self.terminated:
            return

        if not self.is_client and not self.handshake_confirmed:
            self.bytes_received += len(data)

        self.drain_buffered(now)
        offset = 0

        while offset < len(data):
            first = data[offset]

            if not (first & packet.PACKET_FIXED_BIT):
                if first & packet.PACKET_LONG_HEADER:
                    if self.is_client and not self.handshake_complete:
                        self.terminated = True
                        self._events.append(ConnectionTerminated(0x0, "received Version Negotiation packet before handshake"))
                    return
                break

            try:
                if packet.is_long_header(first):
                    consumed = self.receive_long_packet(data, offset, now)
                else:
                    consumed = self.receive_short_packet(data, offset, now)
            except Exception:
                break

            if consumed <= 0:
                break

            offset += consumed
            self.run_handshake()

    def drain_buffered(self, now: float):
        buffered = self.buffered_packets
        if not buffered:
            return

        self.buffered_packets = []
        for raw in buffered:
            try:
                self.receive_long_packet(raw, 0, now)
                self.run_handshake()
            except Exception:
                pass

    def receive_long_packet(self, data: bytes, offset: int, now: float) -> int:
        hdr = packet.parse_long_header(data, offset)

        if hdr.version != packet.QUIC_VERSION_1:
            if hdr.version == 0 and self.is_client and not self.handshake_complete:
                self.terminated = True
                self._events.append(ConnectionTerminated(0x0, "server does not support QUIC version 1"))
            return 0

        if hdr.packet_type == packet.PACKET_TYPE_RETRY:
            if self.is_client and not self.handshake_complete and self._tls_factory is not None:
                self.handle_retry(hdr, data, offset)
            return len(data) - offset

        level = packet.level_for_long_type(hdr.packet_type)

        if self.is_client and not self.remote_cid_set and hdr.source_cid:
            self.remote_cid = hdr.source_cid
            self.remote_cid_set = True

        if not self.is_client and level == LEVEL_INITIAL and not self.recv_keys.get(LEVEL_INITIAL):
            pass

        packet_end = hdr.pn_offset + hdr.length

        keys = self.recv_keys.get(level)
        if keys is None:
            if len(self.buffered_packets) < 16:
                self.buffered_packets.append(bytes(data[offset:packet_end]))
            return packet_end - offset

        plaintext, pn = self.decrypt(data, offset, hdr.pn_offset, keys, level, long_header=True, packet_end=packet_end)
        if plaintext is None:
            return packet_end - offset

        self.process_frames(plaintext, level, pn, now)

        return packet_end - offset

    def receive_short_packet(self, data: bytes, offset: int, now: float) -> int:
        level = LEVEL_APPLICATION
        keys = self.recv_keys.get(level)

        if keys is None:
            return 0

        dcid_start = offset + 1
        dcid_end = dcid_start + len(self.local_cid)
        if len(data) < dcid_end or data[dcid_start:dcid_end] != self.local_cid:
            self._maybe_stateless_reset(data)
            return len(data) - offset

        pn_offset = offset + 1 + len(self.local_cid)
        plaintext, pn = self.decrypt(data, offset, pn_offset, keys, level, long_header=False, packet_end=len(data))

        if plaintext is None:
            self._maybe_stateless_reset(data)
            return len(data) - offset

        self.process_frames(plaintext, level, pn, now)

        return len(data) - offset

    def _maybe_stateless_reset(self, data: bytes):
        # RFC 9000 §10.3: a packet that cannot be associated with a connection
        # may be a Stateless Reset, identified by its trailing 16-byte token.
        if self.terminated:
            return
        if self.peer_stateless_reset_token and len(data) >= 21 and data[-16:] == self.peer_stateless_reset_token:
            self.terminated = True
            self._events.append(ConnectionTerminated(0, "stateless reset"))

    def decrypt(self, data: bytes, offset: int, pn_offset: int, keys: PacketKeys, level: int, *, long_header: bool, packet_end: int):
        buf = bytearray(data[offset:packet_end])
        rel_pn = pn_offset - offset
        sample_at = rel_pn + 4

        if sample_at + 16 > len(buf):
            return None, 0

        sample = bytes(buf[sample_at:sample_at + 16])
        mask = keys.hp.mask(sample)

        if long_header:
            buf[0] ^= mask[0] & 0x0F
        else:
            buf[0] ^= mask[0] & 0x1F

        pn_len = (buf[0] & 0x03) + 1
        truncated = 0

        for i in range(pn_len):
            buf[rel_pn + i] ^= mask[1 + i]
            truncated = (truncated << 8) | buf[rel_pn + i]

        space = level_to_space(level)
        largest = self.largest_recv.get(space, -1)
        pn = packet.decode_packet_number(truncated, pn_len, largest if largest >= 0 else 0)

        if pn in self.recv_pns[space]:
            return None, 0

        header = bytes(buf[:rel_pn + pn_len])
        ciphertext = bytes(buf[rel_pn + pn_len:])

        if long_header:
            try:
                plaintext = keys.decrypt(pn, header, ciphertext)
            except Exception:
                return None, 0
        else:
            plaintext = self._decrypt_application((buf[0] >> 2) & 1, pn, header, ciphertext)
            if plaintext is None:
                return None, 0

        self.recv_pns[space].add(pn)

        new_largest = max(largest, pn)
        self.largest_recv[space] = new_largest

        pns = self.recv_pns[space]

        if len(pns) > 1024:
            cutoff = new_largest - 1024
            self.recv_pns[space] = {p for p in pns if p >= cutoff}

        return plaintext, pn

    def _decrypt_application(self, key_phase_bit: int, pn: int, header: bytes, ciphertext: bytes) -> bytes | None:
        current = self.recv_keys.get(LEVEL_APPLICATION)
        if current is None:
            return None

        if key_phase_bit == (self.recv_key_gen & 1):
            try:
                return current.decrypt(pn, header, ciphertext)
            except Exception:
                return None

        # The Key Phase bit differs: either a peer-initiated key update
        # (next generation) or a reordered packet from the previous generation
        # (RFC 9001 §6.3, §6.4).
        if self.recv_keys_next is not None:
            try:
                plaintext = self.recv_keys_next.decrypt(pn, header, ciphertext)
            except Exception:
                plaintext = None
            if plaintext is not None:
                self._advance_recv_keys()
                if self.send_key_gen < self.recv_key_gen:
                    self._advance_send_keys()  # RFC 9001 §6.1: respond with updated keys
                return plaintext

        if self.recv_keys_prev is not None:
            try:
                return self.recv_keys_prev.decrypt(pn, header, ciphertext)
            except Exception:
                return None

        return None

    def _advance_recv_keys(self):
        self.recv_keys_prev = self.recv_keys[LEVEL_APPLICATION]
        self.recv_keys[LEVEL_APPLICATION] = self.recv_keys_next
        self.recv_keys_next = self.recv_keys[LEVEL_APPLICATION].next_generation()
        self.recv_key_gen += 1

    def _advance_send_keys(self):
        self.send_keys[LEVEL_APPLICATION] = self.send_keys_next
        self.send_keys_next = self.send_keys[LEVEL_APPLICATION].next_generation()
        self.send_key_gen += 1

    def initiate_key_update(self):
        # RFC 9001 §6.2: a key update may only be initiated after the handshake
        # is confirmed; rotate our send keys, and the receive side rotates when
        # the peer responds with the new Key Phase.
        if not self.handshake_confirmed or LEVEL_APPLICATION not in self.send_keys or self.send_keys_next is None:
            return
        if self.send_key_gen > self.recv_key_gen:
            return  # a previously initiated update is still outstanding
        self._advance_send_keys()

    def process_frames(self, plaintext: bytes, level: int, pn: int, now: float):
        space = level_to_space(level)
        buf = Buffer(plaintext)
        ack_eliciting = False

        # Record when the largest packet number in this space arrived, so the
        # ACK Delay field can be reported accurately (RFC 9000 §13.2.5).
        if pn == self.largest_recv.get(space):
            self.largest_recv_time[space] = now

        # RFC 9000 §10.1: restart the idle timer on a successfully processed
        # packet; a subsequent ack-eliciting send may restart it once more.
        self.idle_base = now
        self.ack_eliciting_since_recv = False

        while not buf.eof():
            f = frames.pull_frame(buf)
            ftype = type(f)

            if ftype is not frames.Padding and ftype is not frames.Ack and ftype is not frames.ConnectionClose:
                ack_eliciting = True

            if ftype is frames.Crypto:
                recv = self.crypto_recv[level]
                recv.receive(f.offset, f.data, False)
                chunk = recv.pull()
                if chunk:
                    self.tls.provide_crypto(level, chunk)

            elif ftype is frames.Ack:
                ack_delay_exp = int(self.peer_transport_params.get(TP_ACK_DELAY_EXPONENT, 3) or 3) if self.peer_transport_params else 3
                ack_delay_seconds = f.delay * (2 ** ack_delay_exp) / 1_000_000
                peer_max_ack_delay_ms = int(self.peer_transport_params.get(TP_MAX_ACK_DELAY, 25) or 25) if self.peer_transport_params else 25
                peer_max_ack_delay = peer_max_ack_delay_ms / 1000.0

                acked, lost = self.recovery.on_ack_received(space, f.largest, ack_delay_seconds, f.ranges, now, peer_max_ack_delay)
                self.on_lost(lost)

                if not self.is_client and self.handshake_complete and level == LEVEL_APPLICATION:
                    if LEVEL_HANDSHAKE in self.send_keys or LEVEL_HANDSHAKE in self.recv_keys:
                        self.send_keys.pop(LEVEL_HANDSHAKE, None)
                        self.recv_keys.pop(LEVEL_HANDSHAKE, None)

            elif ftype is frames.Stream:
                self.on_stream_frame(f)

            elif ftype is frames.ResetStream:
                self._events.append(StreamReset(f.stream_id, f.error_code))

            elif ftype is frames.StopSending:
                self._events.append(StopSendingReceived(f.stream_id, f.error_code))

                stream = self.streams.get(f.stream_id)
                if stream is not None and stream.reset_pending is None:
                    stream.reset_pending = (f.error_code, stream.sender.written)

            elif ftype is frames.MaxData:
                if f.maximum > self.peer_max_data:
                    self.data_blocked_pending = False
                self.peer_max_data = max(self.peer_max_data, f.maximum)

            elif ftype is frames.MaxStreamData:
                st = self.streams.get(f.stream_id)

                if st is not None:
                    if f.maximum > st.max_stream_data_remote:
                        st.data_blocked_sent_at = None
                    st.max_stream_data_remote = max(st.max_stream_data_remote, f.maximum)

            elif ftype is frames.PathChallenge:
                self.path_response_pending = f.data

            elif ftype is frames.ConnectionClose:
                self.terminated = True
                self._events.append(ConnectionTerminated(f.error_code, f.reason.decode("utf-8", "replace")))

            elif ftype is frames.MaxStreams:
                if f.bidi:
                    if f.maximum > (self.max_bidi_streams or 0):
                        self.streams_blocked_bidi = False
                    self.max_bidi_streams = max(self.max_bidi_streams or 0, f.maximum)
                else:
                    if f.maximum > (self.max_uni_streams or 0):
                        self.streams_blocked_uni = False
                    self.max_uni_streams = max(self.max_uni_streams or 0, f.maximum)

            elif ftype is frames.NewConnectionId:
                if f.retire_prior_to > f.sequence_number:
                    self.close(0x07, "NEW_CONNECTION_ID: retire_prior_to exceeds sequence_number", application=False)
                    return

                if f.retire_prior_to > 0:
                    self.remote_cid = f.connection_id
                    self.remote_cid_set = True

            elif ftype is frames.RetireConnectionId:
                if f.sequence_number > 0:
                    self.close(0x0a, "RETIRE_CONNECTION_ID references unissued sequence number", application=False)
                    return

            elif ftype is frames.Datagram:
                if self.local_max_datagram_frame_size <= 0 or level != LEVEL_APPLICATION:
                    self.close(0x0a, "PROTOCOL_VIOLATION: unexpected DATAGRAM frame", application=False)
                    return
                if len(f.encode()) > self.local_max_datagram_frame_size:
                    self.close(0x0a, "PROTOCOL_VIOLATION: DATAGRAM exceeds advertised limit", application=False)
                    return
                self._events.append(DatagramReceived(f.data))

            elif ftype is frames.HandshakeDone:
                if level != LEVEL_APPLICATION:
                    self.close(0x0a, "HANDSHAKE_DONE received at wrong encryption level", application=False)
                    return

                if not self.is_client:
                    self.close(0x0a, "HANDSHAKE_DONE must not be sent by client", application=False)
                    return

                self.handshake_confirmed = True
                self.send_keys.pop(LEVEL_INITIAL, None)
                self.recv_keys.pop(LEVEL_INITIAL, None)
                self.send_keys.pop(LEVEL_HANDSHAKE, None)
                self.recv_keys.pop(LEVEL_HANDSHAKE, None)

        if ack_eliciting:
            self.ack_needed[space] = True

        if not self.is_client and level == LEVEL_HANDSHAKE and (LEVEL_INITIAL in self.send_keys or LEVEL_INITIAL in self.recv_keys):
            self.send_keys.pop(LEVEL_INITIAL, None)
            self.recv_keys.pop(LEVEL_INITIAL, None)

    def on_stream_frame(self, f: frames.Stream):
        if f.stream_id not in self.streams:
            peer_initiated = stream_is_client_initiated(f.stream_id) != self.is_client
            if peer_initiated:
                stream_num = f.stream_id >> 2
                limit = self.local_bidi_limit if stream_is_bidirectional(f.stream_id) else self.local_uni_limit
                if stream_num >= limit:
                    self.close(0x04, "STREAM_LIMIT_ERROR: stream ID exceeds local limit", application=False)
                    return

        stream = self.ensure_stream(f.stream_id)

        # RFC 9000 §4.1: enforce the flow control limits we advertised. A peer
        # that sends data beyond the stream or connection limit is a
        # FLOW_CONTROL_ERROR.
        new_end = f.offset + len(f.data)
        if new_end > stream.recv_highest_offset:
            if new_end > stream.max_stream_data_local:
                self.close(0x03, "FLOW_CONTROL_ERROR: stream data beyond advertised limit", application=False)
                return

            delta = new_end - stream.recv_highest_offset
            if self.data_received + delta > self.max_data_local:
                self.close(0x03, "FLOW_CONTROL_ERROR: connection data beyond advertised limit", application=False)
                return

            self.data_received += delta
            stream.recv_highest_offset = new_end

        stream.receiver.receive(f.offset, f.data, f.fin)

        chunk = stream.receiver.pull()
        finished = stream.receiver.finished

        if chunk or finished:
            self._events.append(StreamDataReceived(f.stream_id, chunk, finished))

        # RFC 9000 §4: replenish flow control credit as data is consumed so the
        # peer is not stalled at the initial limit.
        self._extend_stream_credit(stream)
        self._extend_connection_credit()

    def _extend_stream_credit(self, stream: Stream):
        window = DEFAULT_MAX_STREAM_DATA
        if stream.max_stream_data_local - stream.receiver.consumed < window // 2:
            stream.max_stream_data_local = stream.receiver.consumed + window
            stream.max_stream_data_pending = True

    def _extend_connection_credit(self):
        window = DEFAULT_MAX_DATA
        total_consumed = sum(s.receiver.consumed for s in self.streams.values())
        if self.max_data_local - total_consumed < window // 2:
            self.max_data_local = total_consumed + window
            self.max_data_pending = True

    def on_lost(self, lost: list[SentPacket]):
        for pkt in lost:
            for item in pkt.frames:
                kind = item[0]
                if kind == "crypto":
                    _, level, off, length = item
                    self.crypto_send[level].on_loss(off, length, False)
                elif kind == "stream":
                    _, sid, off, length, fin = item
                    st = self.streams.get(sid)
                    if st is not None:
                        st.sender.on_loss(off, length, fin)
                elif kind == "max_data":
                    self.max_data_pending = True
                elif kind == "max_stream_data":
                    st = self.streams.get(item[1])
                    if st is not None:
                        st.max_stream_data_pending = True

    def handle_retry(self, hdr, data: bytes, offset: int) -> None:
        pn_offset = hdr.pn_offset
        if pn_offset + 16 > len(data):
            return

        retry_without_tag = data[offset:pn_offset]
        integrity_tag = data[pn_offset:pn_offset + 16]
        pseudo_packet = bytes([len(self.original_dcid)]) + self.original_dcid + retry_without_tag
        if not verify_retry_integrity_tag(pseudo_packet, integrity_tag):
            return

        self.retry_token = hdr.token

        if not hdr.source_cid:
            return

        new_dcid = hdr.source_cid
        ck, sk = initial_keys(new_dcid)
        self.send_keys[LEVEL_INITIAL] = ck
        self.recv_keys[LEVEL_INITIAL] = sk
        self.remote_cid = new_dcid
        self.remote_cid_set = True

        initial_space = self.recovery.spaces[SPACE_INITIAL]
        for pkt in initial_space.sent.values():
            if pkt.in_flight:
                self.recovery.bytes_in_flight = max(0, self.recovery.bytes_in_flight - pkt.sent_bytes)
        self.recovery.spaces[SPACE_INITIAL] = Space()

        self.next_pn[SPACE_INITIAL] = 0
        self.recv_pns[SPACE_INITIAL] = set()
        self.ack_needed[SPACE_INITIAL] = False
        self.crypto_send[LEVEL_INITIAL] = StreamSender()
        self.crypto_recv[LEVEL_INITIAL] = StreamReceiver()

        try:
            self.tls.reset_for_retry()
        except Exception:
            pass

        self.needs_advance = True

    def datagrams_to_send(self, now: float) -> list[tuple[bytes, int]]:
        # Once terminated, only an endpoint that initiated the close still has a
        # CONNECTION_CLOSE to emit. In the draining state (peer-initiated close)
        # or after an idle timeout, an endpoint MUST NOT send (RFC 9000 §10.2).
        if self.terminated and (self.close_sent or self.close_pending is None):
            return []
        self.run_handshake()

        out: list[bytes] = []
        while True:
            if not self.is_client and not self.handshake_confirmed:
                anti_amp_budget = 3 * self.bytes_received - self.bytes_sent_pre_validation
                if anti_amp_budget <= 0:
                    break

            datagram, progressed = self.build_datagram(now)

            if not progressed:
                break

            out.append(datagram)

            if not self.is_client and not self.handshake_confirmed:
                self.bytes_sent_pre_validation += len(datagram)

            if self.terminated:
                break

        return [(d, 0) for d in out]

    def build_datagram(self, now: float) -> tuple[bytes, bool]:
        datagram = bytearray()
        needs_expansion = False
        progressed = False

        for level in (LEVEL_INITIAL, LEVEL_HANDSHAKE, LEVEL_APPLICATION):
            if level not in self.send_keys:
                continue

            remaining = MAX_DATAGRAM_SIZE - len(datagram)

            if remaining < 64:
                break

            pkt, ack_eliciting = self.build_packet(level, now, remaining)

            if pkt is None:
                continue

            datagram += pkt
            progressed = True

            if level == LEVEL_INITIAL and ack_eliciting:
                needs_expansion = True

        if not progressed:
            return b"", False

        if needs_expansion and len(datagram) < INITIAL_DATAGRAM_MIN:
            datagram += b"\x00" * (INITIAL_DATAGRAM_MIN - len(datagram))

        return bytes(datagram), True

    def build_packet(self, level: int, now: float, max_len: int) -> tuple[bytes | None, bool]:
        space = level_to_space(level)
        payload = bytearray()
        sent_frames: list = []
        ack_eliciting = False

        if self.ack_needed[space] and self.recv_pns[space]:
            ranges = frames.ranges_from_set(self.recv_pns[space])

            # ACK Delay is the time since the largest acked packet arrived,
            # scaled by our ack_delay_exponent (default 3, as we do not send the
            # ack_delay_exponent transport parameter). RFC 9000 §13.2.5, §19.3.
            recv_time = self.largest_recv_time.get(space)
            delay = max(0, int((now - recv_time) * 1_000_000)) >> 3 if recv_time is not None else 0

            ack = frames.Ack(largest=ranges[0][1], delay=delay, ranges=ranges)

            payload += ack.encode()
            self.ack_needed[space] = False

        if self.close_pending is not None:
            close_frame = self.close_pending

            if level != LEVEL_APPLICATION and close_frame.application:
                close_frame = frames.ConnectionClose(0, 0, b"", application=False)

            payload += close_frame.encode()
            self.terminated = True
            self.close_sent = True

        budget = max_len - len(payload) - 64
        crypto = self.crypto_send[level]
        while budget > 16 and crypto.has_data_to_send(1 << 62):
            frame = crypto.get_frame(min(budget, 1100), 1 << 62)
            if frame is None:
                break
            off, cdata, _ = frame
            if not cdata:
                break
            payload += frames.Crypto(off, cdata).encode()
            sent_frames.append(("crypto", level, off, len(cdata)))
            ack_eliciting = True
            budget = max_len - len(payload) - 64

        if level == LEVEL_APPLICATION and self.close_pending is None:
            if self.path_response_pending is not None:
                payload += frames.PathResponse(self.path_response_pending).encode()
                self.path_response_pending = None
                ack_eliciting = True

            if self.handshake_done_pending:
                payload += frames.HandshakeDone().encode()
                self.handshake_done_pending = False
                ack_eliciting = True

            if self.streams_blocked_bidi and max_len - len(payload) > 16:
                payload += frames.StreamsBlocked(self.max_bidi_streams or 0, bidi=True).encode()
                self.streams_blocked_bidi = False
                ack_eliciting = True

            if self.streams_blocked_uni and max_len - len(payload) > 16:
                payload += frames.StreamsBlocked(self.max_uni_streams or 0, bidi=False).encode()
                self.streams_blocked_uni = False
                ack_eliciting = True

            if self.data_blocked_pending and max_len - len(payload) > 16:
                payload += frames.DataBlocked(self.peer_max_data).encode()
                self.data_blocked_pending = False
                ack_eliciting = True

            if self.max_data_pending and max_len - len(payload) > 16:
                payload += frames.MaxData(self.max_data_local).encode()
                self.max_data_pending = False
                sent_frames.append(("max_data",))
                ack_eliciting = True

            # Unreliable DATAGRAM frames (RFC 9221): sent best-effort, never
            # retransmitted on loss, so they are not added to sent_frames.
            sent_count = 0
            for data in self.datagrams_pending:
                encoded = frames.Datagram(data).encode()
                if len(encoded) > max_len - len(payload) - 16:
                    break
                payload += encoded
                ack_eliciting = True
                sent_count += 1
            if sent_count:
                del self.datagrams_pending[:sent_count]

            for stream in self.streams.values():
                if stream.max_stream_data_pending and max_len - len(payload) > 24:
                    payload += frames.MaxStreamData(stream.stream_id, stream.max_stream_data_local).encode()
                    stream.max_stream_data_pending = False
                    sent_frames.append(("max_stream_data", stream.stream_id))
                    ack_eliciting = True

                if stream.reset_pending is not None:
                    err, final = stream.reset_pending
                    payload += frames.ResetStream(stream.stream_id, err, final).encode()
                    stream.reset_pending = None
                    ack_eliciting = True

                budget = max_len - len(payload) - 32
                if budget <= 16:
                    break

                max_offset = stream.max_stream_data_remote
                while budget > 16 and stream.sender.has_data_to_send(max_offset):
                    avail_cwnd = self.recovery.congestion_window - self.recovery.bytes_in_flight
                    if avail_cwnd <= 0:
                        break

                    conn_remaining = self.peer_max_data - self.data_sent
                    if conn_remaining <= 0:
                        self.data_blocked_pending = True
                        break

                    frame = stream.sender.get_frame(
                        min(budget, 1100, max(1, avail_cwnd), conn_remaining),
                        max_offset,
                    )
                    if frame is None:
                        break

                    off, sdata, fin = frame
                    payload += frames.Stream(stream.stream_id, off, sdata, fin).encode()
                    sent_frames.append(("stream", stream.stream_id, off, len(sdata), fin))
                    self.data_sent += len(sdata)
                    ack_eliciting = True
                    budget = max_len - len(payload) - 32

                if (budget > 16
                        and stream.sender.has_data_to_send(1 << 62)
                        and not stream.sender.has_data_to_send(max_offset)
                        and stream.data_blocked_sent_at != max_offset):
                    payload += frames.StreamDataBlocked(stream.stream_id, max_offset).encode()
                    stream.data_blocked_sent_at = max_offset
                    ack_eliciting = True

        if not payload:
            return None, False

        return self.assemble_packet(level, space, bytes(payload), sent_frames, ack_eliciting, now), ack_eliciting

    def assemble_packet(self, level: int, space: int, payload: bytes, sent_frames: list, ack_eliciting: bool, now: float) -> bytes:
        keys = self.send_keys[level]
        pn = self.next_pn[space]

        self.next_pn[space] += 1

        largest_acked = self.recovery.spaces[space].largest_acked
        truncated_pn, pn_len = packet.encode_packet_number(pn, largest_acked)
        pn_bytes = truncated_pn.to_bytes(pn_len, "big")

        payload_len = len(payload) + AEAD_TAG

        if level == LEVEL_APPLICATION:
            prefix, first = packet.serialize_short_header_prefix(self.remote_cid, pn_len, key_phase=bool(self.send_key_gen & 1))
        else:
            ptype = {LEVEL_INITIAL: packet.PACKET_TYPE_INITIAL, LEVEL_HANDSHAKE: packet.PACKET_TYPE_HANDSHAKE}[level]
            token = self.retry_token if level == LEVEL_INITIAL else b""
            prefix, first = packet.serialize_long_header_prefix(ptype, packet.QUIC_VERSION_1, self.remote_cid, self.local_cid, token, pn_len, payload_len)

        header = prefix + pn_bytes
        ciphertext = keys.encrypt(pn, header, payload)

        buf = bytearray(header + ciphertext)
        pn_offset = len(prefix)
        self.apply_header_protection(buf, pn_offset, pn_len, keys, long_header=(level != LEVEL_APPLICATION))

        self.recovery.on_packet_sent(SentPacket(pn, space, now, ack_eliciting, ack_eliciting, len(buf), sent_frames))

        # RFC 9000 §10.1: restart the idle timer when sending the first
        # ack-eliciting packet since the last packet was received.
        if ack_eliciting and not self.ack_eliciting_since_recv and self._effective_idle_timeout() is not None:
            self.idle_base = now
            self.ack_eliciting_since_recv = True

        if self.is_client and level == LEVEL_HANDSHAKE and LEVEL_INITIAL in self.send_keys:
            self.send_keys.pop(LEVEL_INITIAL, None)
            self.recv_keys.pop(LEVEL_INITIAL, None)

        return bytes(buf)

    def apply_header_protection(self, buf: bytearray, pn_offset: int, pn_len: int, keys: PacketKeys, long_header: bool):
        sample_at = pn_offset + 4
        sample = bytes(buf[sample_at:sample_at + 16])
        mask = keys.hp.mask(sample)
        if long_header:
            buf[0] ^= mask[0] & 0x0F
        else:
            buf[0] ^= mask[0] & 0x1F
        for i in range(pn_len):
            buf[pn_offset + i] ^= mask[1 + i]

    def _effective_idle_timeout(self) -> float | None:
        local = self.local_max_idle / 1000.0 if self.local_max_idle else 0.0
        peer = self.peer_max_idle / 1000.0 if self.peer_max_idle else 0.0
        candidates = [v for v in (local, peer) if v > 0]
        return min(candidates) if candidates else None

    def idle_deadline(self) -> float | None:
        timeout = self._effective_idle_timeout()
        if timeout is None or self.idle_base is None:
            return None
        # RFC 9000 §10.1: the connection is not timed out earlier than 3 PTOs.
        return self.idle_base + max(timeout, 3 * self.recovery.pto(self.recovery.peer_max_ack_delay))

    def get_timer(self) -> float | None:
        peer_mad = (
            int(self.peer_transport_params.get(TP_MAX_ACK_DELAY, 25) or 25) / 1000.0
            if self.peer_transport_params
            else 0.025
        )
        loss = self.recovery.get_timer(peer_mad)
        idle = self.idle_deadline()
        candidates = [t for t in (loss, idle) if t is not None]
        return min(candidates) if candidates else None

    def handle_timer(self, now: float):
        idle = self.idle_deadline()
        if idle is not None and now >= idle and not self.terminated:
            # RFC 9000 §10.1: silently close (no CONNECTION_CLOSE) and discard.
            self.terminated = True
            self._events.append(ConnectionTerminated(0, "idle timeout"))
            return

        probes = self.recovery.on_timeout(now)
        self.on_lost(probes)
