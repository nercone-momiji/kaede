from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import LEVEL_INITIAL, LEVEL_EARLY, LEVEL_HANDSHAKE, LEVEL_APPLICATION

K_PACKET_THRESHOLD = 3
K_TIME_THRESHOLD = 9 / 8
K_GRANULARITY = 0.001
K_INITIAL_RTT = 0.333
K_LOSS_REDUCTION_FACTOR = 0.5
K_PERSISTENT_CONGESTION_THRESHOLD = 3

SPACE_INITIAL = 0
SPACE_HANDSHAKE = 1
SPACE_APPLICATION = 2

LEVEL_TO_SPACE = {
    LEVEL_INITIAL: SPACE_INITIAL,
    LEVEL_HANDSHAKE: SPACE_HANDSHAKE,
    LEVEL_EARLY: SPACE_APPLICATION,
    LEVEL_APPLICATION: SPACE_APPLICATION
}

def level_to_space(level: int) -> int:
    return LEVEL_TO_SPACE[level]

@dataclass
class SentPacket:
    packet_number: int
    space: int
    time_sent: float
    ack_eliciting: bool
    in_flight: bool
    sent_bytes: int
    frames: list = field(default_factory=list)

@dataclass
class Space:
    sent: dict[int, SentPacket] = field(default_factory=dict)
    largest_acked: int | None = None
    loss_time: float | None = None
    time_of_last_ack_eliciting: float | None = None

class Recovery:
    def __init__(self, max_datagram_size: int = 1200):
        self.spaces = {SPACE_INITIAL: Space(), SPACE_HANDSHAKE: Space(), SPACE_APPLICATION: Space()}

        self.latest_rtt = 0.0
        self.smoothed_rtt = 0.0
        self.rtt_variance = 0.0
        self.min_rtt = float("inf")
        self.have_rtt = False

        self.pto_count = 0
        self.max_datagram_size = max_datagram_size

        self.initial_window = min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
        self.minimum_window = 2 * max_datagram_size

        self.bytes_in_flight = 0
        self.congestion_window = self.initial_window
        self.ssthresh: int | None = None
        self.congestion_recovery_start_time = 0.0

        self.peer_max_ack_delay = 0.025

    def on_packet_sent(self, packet: SentPacket):
        space = self.spaces[packet.space]
        space.sent[packet.packet_number] = packet

        if packet.in_flight:
            self.bytes_in_flight += packet.sent_bytes

        if packet.ack_eliciting:
            space.time_of_last_ack_eliciting = packet.time_sent

    def on_ack_received(self, space_id: int, largest_acked: int, ack_delay: float, ack_ranges: list[tuple[int, int]], now: float, peer_max_ack_delay: float = 0.025) -> tuple[list[SentPacket], list[SentPacket]]:
        space = self.spaces[space_id]
        space.largest_acked = max(space.largest_acked or 0, largest_acked)

        if space_id == SPACE_APPLICATION:
            self.peer_max_ack_delay = peer_max_ack_delay

        newly_acked: list[SentPacket] = []
        for low, high in ack_ranges:
            for pn in list(space.sent.keys()):
                if low <= pn <= high:
                    newly_acked.append(space.sent.pop(pn))

        if not newly_acked:
            return [], []

        largest = max(p.packet_number for p in newly_acked)
        largest_pkt = next((p for p in newly_acked if p.packet_number == largest), None)
        if largest_pkt is not None and largest_pkt.ack_eliciting and largest == largest_acked:
            self.update_rtt(now - largest_pkt.time_sent, ack_delay, peer_max_ack_delay)

        for pkt in newly_acked:
            if pkt.in_flight:
                self.bytes_in_flight -= pkt.sent_bytes
            self.on_packet_acked(pkt, now)

        self.pto_count = 0
        lost = self.detect_lost_packets(space_id, now)
        return newly_acked, lost

    def update_rtt(self, latest_rtt: float, ack_delay: float, peer_max_ack_delay: float = 0.025):
        self.latest_rtt = latest_rtt
        self.min_rtt = min(self.min_rtt, latest_rtt)

        if not self.have_rtt:
            self.have_rtt = True
            self.smoothed_rtt = latest_rtt
            self.rtt_variance = latest_rtt / 2
            return

        ack_delay = min(ack_delay, peer_max_ack_delay)
        adjusted = latest_rtt
        if latest_rtt > self.min_rtt + ack_delay:
            adjusted = latest_rtt - ack_delay

        self.rtt_variance = 0.75 * self.rtt_variance + 0.25 * abs(self.smoothed_rtt - adjusted)
        self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * adjusted

    def detect_lost_packets(self, space_id: int, now: float) -> list[SentPacket]:
        space = self.spaces[space_id]
        space.loss_time = None
        if space.largest_acked is None:
            return []

        rtt = max(self.latest_rtt, self.smoothed_rtt) if self.have_rtt else K_INITIAL_RTT
        loss_delay = max(K_TIME_THRESHOLD * rtt, K_GRANULARITY)
        lost_send_time = now - loss_delay

        lost: list[SentPacket] = []
        for pn in sorted(space.sent.keys()):
            if pn > space.largest_acked:
                continue
            pkt = space.sent[pn]
            if pkt.time_sent <= lost_send_time or pn <= space.largest_acked - K_PACKET_THRESHOLD:
                lost.append(pkt)
            else:
                if space.loss_time is None:
                    space.loss_time = pkt.time_sent + loss_delay
                else:
                    space.loss_time = min(space.loss_time, pkt.time_sent + loss_delay)

        for pkt in lost:
            del space.sent[pkt.packet_number]
            if pkt.in_flight:
                self.bytes_in_flight -= pkt.sent_bytes

        if lost:
            self.on_packets_lost(lost, now)
        return lost

    def in_congestion_recovery(self, sent_time: float) -> bool:
        return sent_time <= self.congestion_recovery_start_time

    def on_packet_acked(self, pkt: SentPacket, now: float):
        if not pkt.in_flight:
            return

        if self.in_congestion_recovery(pkt.time_sent):
            return

        if self.ssthresh is None or self.congestion_window < self.ssthresh:
            self.congestion_window += pkt.sent_bytes

        else:
            self.congestion_window += self.max_datagram_size * pkt.sent_bytes // max(self.congestion_window, 1)

    def check_persistent_congestion(self, lost: list[SentPacket]) -> bool:
        if not self.have_rtt:
            return False

        ack_eliciting = sorted([p for p in lost if p.ack_eliciting], key=lambda p: p.time_sent)
        if len(ack_eliciting) < 2:
            return False

        span = ack_eliciting[-1].time_sent - ack_eliciting[0].time_sent
        pc_duration = self.pto(self.peer_max_ack_delay) * K_PERSISTENT_CONGESTION_THRESHOLD
        return span >= pc_duration

    def on_packets_lost(self, lost: list[SentPacket], now: float):
        last = max(p.time_sent for p in lost)
        if self.in_congestion_recovery(last):
            return
        self.congestion_recovery_start_time = now
        self.ssthresh = max(int(self.congestion_window * K_LOSS_REDUCTION_FACTOR), self.minimum_window)
        self.congestion_window = self.ssthresh

        if self.check_persistent_congestion(lost):
            self.congestion_window = self.minimum_window
            self.ssthresh = self.minimum_window

    def can_send(self, packet_size: int) -> bool:
        return self.bytes_in_flight + packet_size <= self.congestion_window

    def pto(self, max_ack_delay: float = 0.0) -> float:
        rtt = self.smoothed_rtt if self.have_rtt else K_INITIAL_RTT
        var = self.rtt_variance if self.have_rtt else K_INITIAL_RTT / 2
        return rtt + max(4 * var, K_GRANULARITY) + max_ack_delay

    def get_loss_time(self) -> float | None:
        times = [s.loss_time for s in self.spaces.values() if s.loss_time is not None]
        return min(times) if times else None

    def get_timer(self, peer_max_ack_delay: float = 0.025) -> float | None:
        loss_time = self.get_loss_time()
        if loss_time is not None:
            return loss_time

        best: float | None = None
        for space_id, space in self.spaces.items():
            if space.time_of_last_ack_eliciting is None:
                continue

            mad = peer_max_ack_delay if space_id == SPACE_APPLICATION else 0.0
            pto = self.pto(mad) * (2 ** self.pto_count)
            candidate = space.time_of_last_ack_eliciting + pto
            if best is None or candidate < best:
                best = candidate

        return best

    def on_timeout(self, now: float) -> list[SentPacket]:
        loss_time = self.get_loss_time()
        if loss_time is not None and loss_time <= now:
            out: list[SentPacket] = []
            for space_id in self.spaces:
                out.extend(self.detect_lost_packets(space_id, now))

            return out

        self.pto_count += 1
        probes: list[SentPacket] = []
        for space in self.spaces.values():
            eliciting = [p for p in space.sent.values() if p.ack_eliciting]
            if eliciting:
                eliciting.sort(key=lambda p: p.packet_number)
                probes.extend(eliciting[:2])

        return probes
