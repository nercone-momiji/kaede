from __future__ import annotations

from dataclasses import dataclass
from .packet import Buffer, encode_uint_var

FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_ACK_ECN = 0x03
FRAME_RESET_STREAM = 0x04
FRAME_STOP_SENDING = 0x05
FRAME_CRYPTO = 0x06
FRAME_NEW_TOKEN = 0x07
FRAME_STREAM_BASE = 0x08
FRAME_MAX_DATA = 0x10
FRAME_MAX_STREAM_DATA = 0x11
FRAME_MAX_STREAMS_BIDI = 0x12
FRAME_MAX_STREAMS_UNI = 0x13
FRAME_DATA_BLOCKED = 0x14
FRAME_STREAM_DATA_BLOCKED = 0x15
FRAME_STREAMS_BLOCKED_BIDI = 0x16
FRAME_STREAMS_BLOCKED_UNI = 0x17
FRAME_NEW_CONNECTION_ID = 0x18
FRAME_RETIRE_CONNECTION_ID = 0x19
FRAME_PATH_CHALLENGE = 0x1A
FRAME_PATH_RESPONSE = 0x1B
FRAME_CONNECTION_CLOSE = 0x1C
FRAME_CONNECTION_CLOSE_APP = 0x1D
FRAME_HANDSHAKE_DONE = 0x1E

STREAM_FIN_BIT = 0x01
STREAM_LEN_BIT = 0x02
STREAM_OFF_BIT = 0x04

NON_ACK_ELICITING = frozenset({FRAME_PADDING, FRAME_ACK, FRAME_ACK_ECN, FRAME_CONNECTION_CLOSE, FRAME_CONNECTION_CLOSE_APP})

@dataclass
class Padding:
    length: int = 1
    def encode(self) -> bytes:
        return b"\x00" * self.length

@dataclass
class Ping:
    def encode(self) -> bytes:
        return bytes([FRAME_PING])

@dataclass
class Ack:
    largest: int
    delay: int
    ranges: list[tuple[int, int]]
    ecn: tuple[int, int, int] | None = None

    def encode(self) -> bytes:
        out = bytearray()
        out.append(FRAME_ACK_ECN if self.ecn is not None else FRAME_ACK)

        ranges = self.ranges
        if not ranges:
            out += encode_uint_var(self.largest)
            out += encode_uint_var(self.delay)
            out += encode_uint_var(0)
            out += encode_uint_var(0)
            return bytes(out)

        largest = ranges[0][1]
        first_range = ranges[0][1] - ranges[0][0]

        out += encode_uint_var(largest)
        out += encode_uint_var(self.delay)
        out += encode_uint_var(len(ranges) - 1)
        out += encode_uint_var(first_range)

        prev_low = ranges[0][0]

        for low, high in ranges[1:]:
            gap = prev_low - high - 2
            length = high - low
            out += encode_uint_var(gap)
            out += encode_uint_var(length)
            prev_low = low

        if self.ecn is not None:
            for v in self.ecn:
                out += encode_uint_var(v)

        return bytes(out)

@dataclass
class ResetStream:
    stream_id: int
    error_code: int
    final_size: int

    def encode(self) -> bytes:
        return bytes([FRAME_RESET_STREAM]) + encode_uint_var(self.stream_id) + encode_uint_var(self.error_code) + encode_uint_var(self.final_size)

@dataclass
class StopSending:
    stream_id: int
    error_code: int

    def encode(self) -> bytes:
        return bytes([FRAME_STOP_SENDING]) + encode_uint_var(self.stream_id) + encode_uint_var(self.error_code)

@dataclass
class Crypto:
    offset: int
    data: bytes

    def encode(self) -> bytes:
        return bytes([FRAME_CRYPTO]) + encode_uint_var(self.offset) + encode_uint_var(len(self.data)) + self.data

@dataclass
class NewToken:
    token: bytes

    def encode(self) -> bytes:
        return bytes([FRAME_NEW_TOKEN]) + encode_uint_var(len(self.token)) + self.token

@dataclass
class Stream:
    stream_id: int
    offset: int
    data: bytes
    fin: bool

    def encode(self) -> bytes:
        type_byte = FRAME_STREAM_BASE | STREAM_LEN_BIT

        if self.offset:
            type_byte |= STREAM_OFF_BIT

        if self.fin:
            type_byte |= STREAM_FIN_BIT

        out = bytes([type_byte]) + encode_uint_var(self.stream_id)

        if self.offset:
            out += encode_uint_var(self.offset)

        out += encode_uint_var(len(self.data)) + self.data

        return out

@dataclass
class MaxData:
    maximum: int

    def encode(self) -> bytes:
        return bytes([FRAME_MAX_DATA]) + encode_uint_var(self.maximum)

@dataclass
class MaxStreamData:
    stream_id: int
    maximum: int

    def encode(self) -> bytes:
        return bytes([FRAME_MAX_STREAM_DATA]) + encode_uint_var(self.stream_id) + encode_uint_var(self.maximum)

@dataclass
class MaxStreams:
    maximum: int
    bidi: bool

    def encode(self) -> bytes:
        return bytes([FRAME_MAX_STREAMS_BIDI if self.bidi else FRAME_MAX_STREAMS_UNI]) + encode_uint_var(self.maximum)

@dataclass
class DataBlocked:
    limit: int

    def encode(self) -> bytes:
        return bytes([FRAME_DATA_BLOCKED]) + encode_uint_var(self.limit)

@dataclass
class StreamDataBlocked:
    stream_id: int
    limit: int

    def encode(self) -> bytes:
        return bytes([FRAME_STREAM_DATA_BLOCKED]) + encode_uint_var(self.stream_id) + encode_uint_var(self.limit)

@dataclass
class StreamsBlocked:
    limit: int
    bidi: bool

    def encode(self) -> bytes:
        return bytes([FRAME_STREAMS_BLOCKED_BIDI if self.bidi else FRAME_STREAMS_BLOCKED_UNI]) + encode_uint_var(self.limit)

@dataclass
class NewConnectionId:
    sequence_number: int
    retire_prior_to: int
    connection_id: bytes
    stateless_reset_token: bytes

    def encode(self) -> bytes:
        return (bytes([FRAME_NEW_CONNECTION_ID]) + encode_uint_var(self.sequence_number) + encode_uint_var(self.retire_prior_to)
                + bytes([len(self.connection_id)]) + self.connection_id + self.stateless_reset_token)

@dataclass
class RetireConnectionId:
    sequence_number: int

    def encode(self) -> bytes:
        return bytes([FRAME_RETIRE_CONNECTION_ID]) + encode_uint_var(self.sequence_number)

@dataclass
class PathChallenge:
    data: bytes

    def encode(self) -> bytes:
        return bytes([FRAME_PATH_CHALLENGE]) + self.data

@dataclass
class PathResponse:
    data: bytes

    def encode(self) -> bytes:
        return bytes([FRAME_PATH_RESPONSE]) + self.data

@dataclass
class ConnectionClose:
    error_code: int
    frame_type: int
    reason: bytes
    application: bool = False

    def encode(self) -> bytes:
        out = bytearray([FRAME_CONNECTION_CLOSE_APP if self.application else FRAME_CONNECTION_CLOSE])
        out += encode_uint_var(self.error_code)

        if not self.application:
            out += encode_uint_var(self.frame_type)

        out += encode_uint_var(len(self.reason))
        out += self.reason

        return bytes(out)

@dataclass
class HandshakeDone:
    def encode(self) -> bytes:
        return bytes([FRAME_HANDSHAKE_DONE])

def pull_frame(buf: Buffer):
    frame_type = buf.pull_uint_var()

    if frame_type == FRAME_PADDING:
        length = 1

        while not buf.eof() and buf._data[buf.pos] == 0:
            buf.pos += 1
            length += 1

        return Padding(length)

    if frame_type == FRAME_PING:
        return Ping()

    if frame_type in (FRAME_ACK, FRAME_ACK_ECN):
        largest = buf.pull_uint_var()
        delay = buf.pull_uint_var()
        range_count = buf.pull_uint_var()
        first_range = buf.pull_uint_var()

        ranges: list[tuple[int, int]] = [(largest - first_range, largest)]
        low = largest - first_range

        for _ in range(range_count):
            gap = buf.pull_uint_var()
            length = buf.pull_uint_var()
            high = low - gap - 2
            low = high - length
            ranges.append((low, high))

        ecn = None
        if frame_type == FRAME_ACK_ECN:
            ecn = (buf.pull_uint_var(), buf.pull_uint_var(), buf.pull_uint_var())

        return Ack(largest, delay, ranges, ecn)

    if frame_type == FRAME_RESET_STREAM:
        return ResetStream(buf.pull_uint_var(), buf.pull_uint_var(), buf.pull_uint_var())

    if frame_type == FRAME_STOP_SENDING:
        return StopSending(buf.pull_uint_var(), buf.pull_uint_var())

    if frame_type == FRAME_CRYPTO:
        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        return Crypto(offset, buf.pull_bytes(length))

    if frame_type == FRAME_NEW_TOKEN:
        length = buf.pull_uint_var()
        return NewToken(buf.pull_bytes(length))

    if FRAME_STREAM_BASE <= frame_type <= 0x0F:
        stream_id = buf.pull_uint_var()
        offset = buf.pull_uint_var() if frame_type & STREAM_OFF_BIT else 0

        if frame_type & STREAM_LEN_BIT:
            length = buf.pull_uint_var()
            data = buf.pull_bytes(length)

        else:
            data = buf.pull_bytes(buf.remaining())

        return Stream(stream_id, offset, data, bool(frame_type & STREAM_FIN_BIT))

    if frame_type == FRAME_MAX_DATA:
        return MaxData(buf.pull_uint_var())

    if frame_type == FRAME_MAX_STREAM_DATA:
        return MaxStreamData(buf.pull_uint_var(), buf.pull_uint_var())

    if frame_type in (FRAME_MAX_STREAMS_BIDI, FRAME_MAX_STREAMS_UNI):
        return MaxStreams(buf.pull_uint_var(), frame_type == FRAME_MAX_STREAMS_BIDI)

    if frame_type == FRAME_DATA_BLOCKED:
        return DataBlocked(buf.pull_uint_var())

    if frame_type == FRAME_STREAM_DATA_BLOCKED:
        return StreamDataBlocked(buf.pull_uint_var(), buf.pull_uint_var())

    if frame_type in (FRAME_STREAMS_BLOCKED_BIDI, FRAME_STREAMS_BLOCKED_UNI):
        return StreamsBlocked(buf.pull_uint_var(), frame_type == FRAME_STREAMS_BLOCKED_BIDI)

    if frame_type == FRAME_NEW_CONNECTION_ID:
        seq = buf.pull_uint_var()
        retire = buf.pull_uint_var()
        cid_len = buf.pull_uint8()
        cid = buf.pull_bytes(cid_len)
        token = buf.pull_bytes(16)
        return NewConnectionId(seq, retire, cid, token)

    if frame_type == FRAME_RETIRE_CONNECTION_ID:
        return RetireConnectionId(buf.pull_uint_var())

    if frame_type == FRAME_PATH_CHALLENGE:
        return PathChallenge(buf.pull_bytes(8))

    if frame_type == FRAME_PATH_RESPONSE:
        return PathResponse(buf.pull_bytes(8))

    if frame_type in (FRAME_CONNECTION_CLOSE, FRAME_CONNECTION_CLOSE_APP):
        error_code = buf.pull_uint_var()
        inner_type = buf.pull_uint_var() if frame_type == FRAME_CONNECTION_CLOSE else 0
        reason_len = buf.pull_uint_var()
        reason = buf.pull_bytes(reason_len)
        return ConnectionClose(error_code, inner_type, reason, frame_type == FRAME_CONNECTION_CLOSE_APP)

    if frame_type == FRAME_HANDSHAKE_DONE:
        return HandshakeDone()

    raise ValueError(f"unknown frame type 0x{frame_type:x}")

def ranges_from_set(acked: set[int]) -> list[tuple[int, int]]:
    if not acked:
        return []

    numbers = sorted(acked, reverse=True)
    ranges: list[tuple[int, int]] = []
    high = low = numbers[0]

    for n in numbers[1:]:
        if n == low - 1:
            low = n
        else:
            ranges.append((low, high))
            high = low = n

    ranges.append((low, high))
    return ranges
