from __future__ import annotations

import os
from dataclasses import dataclass

from . import frame as frames
from . import packet
from .packet import Buffer, encode_uint_var
from .crypto import LEVEL_INITIAL, LEVEL_HANDSHAKE, LEVEL_APPLICATION,PacketKeys, suite_for, initial_keys, INITIAL_CIPHER
from .stream import Stream, StreamSender, StreamReceiver, stream_is_bidirectional, stream_is_client_initiated
from .recovery import Recovery, SentPacket, Space, level_to_space, SPACE_INITIAL, SPACE_HANDSHAKE, SPACE_APPLICATION
from .tls import QuicTLS

MAX_DATAGRAM_SIZE = 1350
INITIAL_DATAGRAM_MIN = 1200
AEAD_TAG = 16

TP_ORIGINAL_DCID = 0x00
TP_MAX_IDLE_TIMEOUT = 0x01
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
        if tp_id in (TP_ORIGINAL_DCID, TP_INITIAL_SCID):
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

        self.recovery = Recovery(MAX_DATAGRAM_SIZE)
        self._events: list = []

        self.send_keys: dict[int, PacketKeys] = {}
        self.recv_keys: dict[int, PacketKeys] = {}
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
        self.ack_needed = {SPACE_INITIAL: False, SPACE_HANDSHAKE: False, SPACE_APPLICATION: False}

        self.streams: dict[int, Stream] = {}
        self.next_uni = 2 if is_client else 3
        self.next_bidi = 0 if is_client else 1
        self.peer_transport_params: dict[int, int | bytes] = {}
        self.peer_max_data = DEFAULT_MAX_DATA
        self.max_bidi_streams: int | None = None
        self.max_uni_streams: int | None = None
        self.data_sent = 0
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
            TP_MAX_UDP_PAYLOAD: MAX_DATAGRAM_SIZE
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
        remote_cid = hdr.source_cid
        local_cid = os.urandom(8)

        tp = {
            TP_ORIGINAL_DCID: original_dcid,
            TP_INITIAL_SCID: local_cid,
            TP_INITIAL_MAX_DATA: DEFAULT_MAX_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAM_DATA_UNI: DEFAULT_MAX_STREAM_DATA,
            TP_INITIAL_MAX_STREAMS_BIDI: DEFAULT_MAX_STREAMS,
            TP_INITIAL_MAX_STREAMS_UNI: DEFAULT_MAX_STREAMS,
            TP_ACTIVE_CONNECTION_ID_LIMIT: 2,
            TP_MAX_IDLE_TIMEOUT: 30000,
            TP_MAX_UDP_PAYLOAD: MAX_DATAGRAM_SIZE
        }

        if local_tp_extra:
            tp.update(local_tp_extra)

        tls = tls_factory(encode_transport_parameters(tp))

        return cls(is_client=False, tls=tls, original_dcid=original_dcid, local_cid=local_cid, remote_cid=remote_cid)

    def get_next_available_stream_id(self, is_bidi: bool = True) -> int:
        if is_bidi:
            if self.max_bidi_streams is not None and self.next_bidi // 4 >= self.max_bidi_streams:
                raise ConnectionError("peer bidirectional stream limit reached")
            sid = self.next_bidi
            self.next_bidi += 4
        else:
            base = 2 if self.is_client else 3
            if self.max_uni_streams is not None and (self.next_uni - base) // 4 >= self.max_uni_streams:
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
                    self.close(0x10, "original_destination_connection_id mismatch", application=False)
                    return

            self.peer_max_data = int(self.peer_transport_params.get(TP_INITIAL_MAX_DATA, DEFAULT_MAX_DATA) or 0)
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
                self.handle_retry(hdr)
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
            return len(data) - offset

        pn_offset = offset + 1 + len(self.local_cid)
        plaintext, pn = self.decrypt(data, offset, pn_offset, keys, level, long_header=False, packet_end=len(data))

        if plaintext is None:
            return len(data) - offset

        self.process_frames(plaintext, level, pn, now)

        return len(data) - offset

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
        try:
            plaintext = keys.decrypt(pn, header, ciphertext)
        except Exception:
            return None, 0

        self.recv_pns[space].add(pn)

        new_largest = max(largest, pn)
        self.largest_recv[space] = new_largest

        pns = self.recv_pns[space]

        if len(pns) > 1024:
            cutoff = new_largest - 1024
            self.recv_pns[space] = {p for p in pns if p >= cutoff}

        return plaintext, pn

    def process_frames(self, plaintext: bytes, level: int, pn: int, now: float):
        space = level_to_space(level)
        buf = Buffer(plaintext)
        ack_eliciting = False

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
                self.peer_max_data = max(self.peer_max_data, f.maximum)

            elif ftype is frames.MaxStreamData:
                st = self.streams.get(f.stream_id)

                if st is not None:
                    st.max_stream_data_remote = max(st.max_stream_data_remote, f.maximum)

            elif ftype is frames.PathChallenge:
                self.path_response_pending = f.data

            elif ftype is frames.ConnectionClose:
                self.terminated = True
                self._events.append(ConnectionTerminated(f.error_code, f.reason.decode("utf-8", "replace")))

            elif ftype is frames.MaxStreams:
                if f.bidi:
                    self.max_bidi_streams = max(self.max_bidi_streams or 0, f.maximum)
                else:
                    self.max_uni_streams = max(self.max_uni_streams or 0, f.maximum)

            elif ftype is frames.NewConnectionId:
                if f.retire_prior_to > 0:
                    self.remote_cid = f.connection_id
                    self.remote_cid_set = True

            elif ftype is frames.RetireConnectionId:
                if f.sequence_number > 0:
                    self.close(0x0a, "RETIRE_CONNECTION_ID references unissued sequence number", application=False)
                    return

            elif ftype is frames.HandshakeDone:
                if level != LEVEL_APPLICATION:
                    self.close(0x0a, "HANDSHAKE_DONE received at wrong encryption level", application=False)
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
        stream.receiver.receive(f.offset, f.data, f.fin)

        chunk = stream.receiver.pull()
        finished = stream.receiver.finished

        if chunk or finished:
            self._events.append(StreamDataReceived(f.stream_id, chunk, finished))

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

    def handle_retry(self, hdr) -> None:
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
        if self.terminated and self.close_sent:
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
            ack = frames.Ack(largest=ranges[0][1], delay=0, ranges=ranges)

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

            for stream in self.streams.values():
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

                    frame = stream.sender.get_frame(min(budget, 1100, max(1, avail_cwnd)), max_offset)
                    if frame is None:
                        break

                    off, sdata, fin = frame
                    payload += frames.Stream(stream.stream_id, off, sdata, fin).encode()
                    sent_frames.append(("stream", stream.stream_id, off, len(sdata), fin))
                    ack_eliciting = True
                    budget = max_len - len(payload) - 32

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
            prefix, first = packet.serialize_short_header_prefix(self.remote_cid, pn_len)
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

    def get_timer(self) -> float | None:
        return self.recovery.get_timer()

    def handle_timer(self, now: float):
        probes = self.recovery.on_timeout(now)
        self.on_lost(probes)
