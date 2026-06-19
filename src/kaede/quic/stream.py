from __future__ import annotations

def stream_is_client_initiated(stream_id: int) -> bool:
    return (stream_id & 0x1) == 0

def stream_is_bidirectional(stream_id: int) -> bool:
    return (stream_id & 0x2) == 0

class RangeSet:
    def __init__(self):
        self.ranges: list[list[int]] = []

    def __bool__(self) -> bool:
        return bool(self.ranges)

    def __iter__(self):
        return iter(self.ranges)

    def add(self, start: int, stop: int):
        if stop <= start:
            return

        merged: list[list[int]] = []
        placed = False

        for rng in self.ranges:
            if rng[1] < start:
                merged.append(rng)

            elif stop < rng[0]:
                if not placed:
                    merged.append([start, stop])
                    placed = True
                merged.append(rng)

            else:
                start = min(start, rng[0])
                stop = max(stop, rng[1])

        if not placed:
            merged.append([start, stop])

        merged.sort()

        coalesced: list[list[int]] = []

        for rng in merged:
            if coalesced and rng[0] <= coalesced[-1][1]:
                coalesced[-1][1] = max(coalesced[-1][1], rng[1])
            else:
                coalesced.append(rng)

        self.ranges = coalesced

    def subtract(self, start: int, stop: int):
        if stop <= start:
            return

        out: list[list[int]] = []

        for lo, hi in self.ranges:
            if hi <= start or lo >= stop:
                out.append([lo, hi])
                continue

            if lo < start:
                out.append([lo, start])

            if hi > stop:
                out.append([stop, hi])

        self.ranges = out

    def first(self) -> list[int] | None:
        return self.ranges[0] if self.ranges else None

    def contains(self, value: int) -> bool:
        for lo, hi in self.ranges:
            if lo <= value < hi:
                return True
        return False

class StreamSender:
    def __init__(self):
        self.data = bytearray()
        self.base = 0
        self.written = 0
        self.pending = RangeSet()
        self.acked = RangeSet()
        self.fin = False
        self.fin_offset: int | None = None
        self.fin_pending = False
        self.fin_acked = False

    def write(self, data: bytes, fin: bool = False):
        if data:
            start = self.written
            self.data.extend(data)
            self.written += len(data)
            self.pending.add(start, self.written)

        if fin and not self.fin:
            self.fin = True
            self.fin_offset = self.written
            self.fin_pending = True

    @property
    def finished(self) -> bool:
        return self.fin_acked

    def has_data_to_send(self, max_offset: int) -> bool:
        rng = self.pending.first()

        if rng is not None and rng[0] < max_offset:
            return True

        return self.fin_pending and (self.fin_offset is not None) and self.fin_offset <= max_offset

    def get_frame(self, max_size: int, max_offset: int) -> tuple[int, bytes, bool] | None:
        rng = self.pending.first()
        offset = None
        data = b""

        if rng is not None and rng[0] < max_offset:
            offset = rng[0]
            stop = min(rng[1], offset + max_size, max_offset)
            data = bytes(self.data[offset - self.base:stop - self.base])
            self.pending.subtract(offset, stop)

        send_fin = False

        if self.fin_pending and self.fin_offset is not None:
            end = (offset + len(data)) if offset is not None else self.written
            if (offset is None or self.pending.first() is None) and end >= self.fin_offset and self.fin_offset <= max_offset:
                send_fin = True
                self.fin_pending = False
                if offset is None:
                    offset = self.fin_offset

        if offset is None and not send_fin:
            return None

        return offset, data, send_fin

    def on_ack(self, offset: int, length: int, fin: bool):
        if length:
            self.acked.add(offset, offset + length)
            first = self.acked.first()
            if first is not None and first[0] <= self.base:
                discard = first[1] - self.base
                if discard > 0:
                    del self.data[:discard]
                    self.base = first[1]

        if fin:
            self.fin_acked = True

    def on_loss(self, offset: int, length: int, fin: bool):
        if length:
            self.pending.add(offset, offset + length)

        if fin:
            self.fin_pending = True

MAX_STREAM_RECEIVE_BUFFER = 8 * 1024 * 1024

class StreamReceiver:
    def __init__(self):
        self.buffer = bytearray()
        self.received = RangeSet()
        self.consumed = 0
        self.fin_offset: int | None = None

    def receive(self, offset: int, data: bytes, fin: bool):
        if fin:
            self.fin_offset = offset + len(data)

        end = offset + len(data)

        if end <= self.consumed:
            return

        if offset < self.consumed:
            data = data[self.consumed - offset:]
            offset = self.consumed

        index = offset - self.consumed
        need = index + len(data)

        if need > MAX_STREAM_RECEIVE_BUFFER:
            raise ValueError(f"stream receive buffer would exceed limit ({need} > {MAX_STREAM_RECEIVE_BUFFER})")

        if need > len(self.buffer):
            self.buffer.extend(b"\x00" * (need - len(self.buffer)))

        self.buffer[index:index + len(data)] = data
        self.received.add(offset, end)

    def pull(self) -> bytes:
        first = self.received.first()
        if first is None or first[0] > self.consumed:
            return b""

        n = first[1] - self.consumed
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        self.consumed = first[1]
        return out

    @property
    def finished(self) -> bool:
        return self.fin_offset is not None and self.consumed >= self.fin_offset

class Stream:
    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self.sender = StreamSender()
        self.receiver = StreamReceiver()
        self.max_stream_data_local = 0
        self.max_stream_data_remote = 0
        self.reset_pending: tuple[int, int] | None = None
        self.stop_sending_pending: int | None = None
        self.is_bidi = stream_is_bidirectional(stream_id)
        self.data_blocked_sent_at: int | None = None
        self.recv_highest_offset = 0
        self.max_stream_data_pending = False
