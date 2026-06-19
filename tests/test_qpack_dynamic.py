"""
RFC 9204 §3.2 / §4.4 / §4.5: QPACK dynamic table and dynamic-reference decoding.
"""
from __future__ import annotations

import pytest
from kaede.http.qpack import (
    QpackError,
    DynamicTable,
    QpackDecoder,
    encode_integer,
    encode_string,
    STATICtable,
)


# ---------------------------------------------------------------------------
# Encoder-stream instruction builders (hand-crafted per RFC 9204 §3.2)
# ---------------------------------------------------------------------------

def _set_capacity(cap: int) -> bytes:
    """Set Dynamic Table Capacity: 001 cap[5+]"""
    return encode_integer(cap, 5, 0x20)


def _insert_literal(name: bytes, value: bytes) -> bytes:
    """Insert with Literal Name: 01 0 name[5+] value[7+]"""
    return encode_string(name, 5, 0x40) + encode_string(value, 7, 0x00)


def _insert_name_ref_static(static_idx: int, value: bytes) -> bytes:
    """Insert with Name Reference (static): 1 1 idx[6+] value[7+]"""
    return encode_integer(static_idx, 6, 0xC0) + encode_string(value, 7, 0x00)


def _insert_name_ref_dynamic(relative_idx: int, value: bytes) -> bytes:
    """Insert with Name Reference (dynamic, relative): 1 0 idx[6+] value[7+]"""
    return encode_integer(relative_idx, 6, 0x80) + encode_string(value, 7, 0x00)


def _duplicate(relative_idx: int) -> bytes:
    """Duplicate: 000 idx[5+]"""
    return encode_integer(relative_idx, 5, 0x00)


# ---------------------------------------------------------------------------
# Field-section byte builders (RFC 9204 §4.5)
# ---------------------------------------------------------------------------

def _prefix(enc_ric: int, s_bit: bool, delta_base: int) -> bytes:
    """Field section 2-byte prefix: enc_ric[8+] S delta_base[7+]"""
    return encode_integer(enc_ric, 8, 0x00) + encode_integer(delta_base, 7, 0x80 if s_bit else 0x00)


def _static_indexed(idx: int) -> bytes:
    """Indexed Field Line – static: 1 1 idx[6+]"""
    return encode_integer(idx, 6, 0xC0)


def _dynamic_indexed(relative_idx: int) -> bytes:
    """Indexed Field Line – dynamic, pre-base relative: 1 0 idx[6+]"""
    return encode_integer(relative_idx, 6, 0x80)


def _post_base_indexed(post_base_idx: int) -> bytes:
    """Indexed Field Line with Post-Base Index: 0001 idx[4+]"""
    return encode_integer(post_base_idx, 4, 0x10)


def _literal_name_ref_static(static_idx: int, value: bytes) -> bytes:
    """Literal Field Line with Name Reference (static): 01 1 N idx[4+] value"""
    return encode_integer(static_idx, 4, 0x50) + encode_string(value, 7, 0x00)


def _literal_name_ref_dynamic(relative_idx: int, value: bytes) -> bytes:
    """Literal Field Line with Name Reference (dynamic): 01 0 N idx[4+] value"""
    return encode_integer(relative_idx, 4, 0x40) + encode_string(value, 7, 0x00)


def _post_base_literal(post_base_idx: int, value: bytes) -> bytes:
    """Literal Field Line with Post-Base Name Reference: 0000 N idx[3+] value"""
    return encode_integer(post_base_idx, 3, 0x00) + encode_string(value, 7, 0x00)


def _literal_name(name: bytes, value: bytes) -> bytes:
    """Literal Field Line with Literal Name: 001 N H name[3+] value"""
    return encode_string(name, 3, 0x20) + encode_string(value, 7, 0x00)


# ---------------------------------------------------------------------------
# DynamicTable unit tests (RFC 9204 §3.2)
# ---------------------------------------------------------------------------

class TestDynamicTable:
    def test_initial_state(self):
        t = DynamicTable(capacity=4096)
        assert t.insert_count == 0
        assert t.capacity == 4096

    def test_insert_and_get(self):
        t = DynamicTable(capacity=4096)
        idx = t.insert(b"foo", b"bar")
        assert idx == 0
        assert t.get(0) == (b"foo", b"bar")
        assert t.insert_count == 1

    def test_entry_overhead_is_32_bytes(self):
        # RFC 9204 §3.2.1: entry size = len(name) + len(value) + 32
        # capacity=34 fits exactly one entry with 1-byte name and 1-byte value
        t = DynamicTable(capacity=34)
        t.insert(b"a", b"b")
        assert t.insert_count == 1

    def test_entry_that_fills_exactly(self):
        # Entry of size 36 in a table with capacity 68 leaves room for exactly one more
        t = DynamicTable(capacity=72)
        t.insert(b"ab", b"cd")   # 2+2+32=36 bytes, abs=0
        t.insert(b"ef", b"gh")   # 2+2+32=36 bytes, abs=1; total=72
        assert t.insert_count == 2

    def test_eviction_on_overflow(self):
        # capacity=68: room for two 34-byte entries.  A third evicts the oldest.
        t = DynamicTable(capacity=68)
        t.insert(b"a", b"b")   # abs 0
        t.insert(b"c", b"d")   # abs 1
        t.insert(b"e", b"f")   # abs 2; evicts abs 0
        assert t.insert_count == 3
        with pytest.raises(QpackError):
            t.get(0)           # evicted
        assert t.get(1) == (b"c", b"d")
        assert t.get(2) == (b"e", b"f")

    def test_insert_count_increases_monotonically(self):
        t = DynamicTable(capacity=68)
        t.insert(b"a", b"b")
        t.insert(b"c", b"d")
        t.insert(b"e", b"f")   # evicts entry 0
        # insert_count never goes backwards
        assert t.insert_count == 3

    def test_entry_too_large_raises(self):
        t = DynamicTable(capacity=64)
        with pytest.raises(QpackError):
            t.insert(b"x" * 100, b"y")

    def test_set_capacity_evicts_entries(self):
        t = DynamicTable(capacity=4096)
        t.insert(b"name", b"value")   # 4+5+32=41 bytes, abs 0
        t.set_capacity(30)            # 41 > 30 → evicted
        assert t.insert_count == 1
        with pytest.raises(QpackError):
            t.get(0)

    def test_set_capacity_zero_clearstable(self):
        t = DynamicTable(capacity=4096)
        t.insert(b"a", b"b")
        t.set_capacity(0)
        assert t.insert_count == 1   # count doesn't regress
        with pytest.raises(QpackError):
            t.get(0)

    def test_max_entries(self):
        # max_entries = floor(capacity / 32) (§4.5.1.1)
        assert DynamicTable(capacity=320).max_entries == 10
        assert DynamicTable(capacity=4096).max_entries == 128
        assert DynamicTable(capacity=0).max_entries == 0

    def test_get_out_of_range_raises(self):
        t = DynamicTable(capacity=4096)
        with pytest.raises(QpackError):
            t.get(99)


# ---------------------------------------------------------------------------
# QpackDecoder encoder stream (RFC 9204 §3.2)
# ---------------------------------------------------------------------------

class TestEncoderStreamInstructions:
    def _dec(self, max_capacity: int = 4096) -> QpackDecoder:
        d = QpackDecoder(max_capacity=max_capacity)
        d.feed_encoder_stream(_set_capacity(max_capacity))
        return d

    def test_set_capacity(self):
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(512))
        assert d.table.capacity == 512

    def test_set_capacity_above_max_raises(self):
        d = QpackDecoder(max_capacity=1024)
        with pytest.raises(QpackError):
            d.feed_encoder_stream(_set_capacity(2048))

    def test_insert_literal_name(self):
        d = self._dec()
        d.feed_encoder_stream(_insert_literal(b"x-custom", b"hello"))
        assert d.table.insert_count == 1
        assert d.table.get(0) == (b"x-custom", b"hello")

    def test_insert_literal_lowercases_name(self):
        d = self._dec()
        d.feed_encoder_stream(_insert_literal(b"X-Custom", b"Val"))
        name, _ = d.table.get(0)
        assert name == b"x-custom"

    def test_insert_name_ref_static(self):
        d = self._dec()
        # Static index 17 = (:method, GET); insert with value "POST"
        d.feed_encoder_stream(_insert_name_ref_static(17, b"POST"))
        assert d.table.insert_count == 1
        name, value = d.table.get(0)
        assert name == b":method"
        assert value == b"POST"

    def test_insert_name_ref_dynamic(self):
        d = self._dec()
        d.feed_encoder_stream(_insert_literal(b"x-base", b"base"))  # abs 0
        # Dynamic relative index 0 = most recently inserted (abs 0)
        d.feed_encoder_stream(_insert_name_ref_dynamic(0, b"derived"))  # abs 1
        assert d.table.insert_count == 2
        assert d.table.get(1) == (b"x-base", b"derived")

    def test_duplicate(self):
        d = self._dec()
        d.feed_encoder_stream(_insert_literal(b"foo", b"bar"))  # abs 0
        d.feed_encoder_stream(_duplicate(0))                     # abs 1 (copy of 0)
        assert d.table.insert_count == 2
        assert d.table.get(0) == (b"foo", b"bar")
        assert d.table.get(1) == (b"foo", b"bar")

    def test_multiple_instructions_in_one_feed(self):
        d = self._dec()
        data = _insert_literal(b"a", b"1") + _insert_literal(b"b", b"2")
        d.feed_encoder_stream(data)
        assert d.table.insert_count == 2

    def test_partial_instruction_buffered(self):
        d = QpackDecoder(max_capacity=4096)
        full = _set_capacity(512)
        # Send only the first byte; the instruction is not yet complete
        d.feed_encoder_stream(full[:1])
        assert d.table.capacity == 0   # not yet applied
        d.feed_encoder_stream(full[1:])
        assert d.table.capacity == 512

    def test_insert_count_increment_emitted(self):
        d = self._dec()
        d.feed_encoder_stream(_insert_literal(b"a", b"1"))
        d.feed_encoder_stream(_insert_literal(b"b", b"2"))
        instructions = d.flush_decoder_instructions()
        # ICI=2: 00 000010 = 0x02
        assert instructions[0] == 0x02

    def test_flush_clears_pending(self):
        d = self._dec()
        d.feed_encoder_stream(_insert_literal(b"a", b"1"))
        d.flush_decoder_instructions()
        assert d.flush_decoder_instructions() == b""


# ---------------------------------------------------------------------------
# QpackDecoder field section decoding (RFC 9204 §4.5)
# ---------------------------------------------------------------------------

class TestFieldSectionDecoding:
    def _dec_with_entry(self) -> tuple[QpackDecoder, int]:
        """Return a decoder with one dynamic entry and its absolute index."""
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(4096))
        d.feed_encoder_stream(_insert_literal(b"x-test", b"value"))
        d.flush_decoder_instructions()   # clear ICI
        return d, 0   # entry at absolute index 0

    def _ric_enc(self, ric: int, max_entries: int) -> int:
        full_range = 2 * max_entries
        return (ric % full_range) + 1

    def test_static_only_zero_ric(self):
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(4096))
        # RIC=0, S=0, delta=0; static index 17 = (:method, GET)
        data = _prefix(0, False, 0) + _static_indexed(17)
        headers = d.decode_field_section(data)
        assert (b":method", b"GET") in headers

    def test_literal_name_in_field_section(self):
        d = QpackDecoder(max_capacity=4096)
        data = _prefix(0, False, 0) + _literal_name(b"x-foo", b"bar")
        headers = d.decode_field_section(data)
        assert (b"x-foo", b"bar") in headers

    def test_dynamic_indexed_field(self):
        d, _ = self._dec_with_entry()
        # insert_count=1, MaxEntries=128, enc_ric=(1%256)+1=2
        # base = ric + delta = 1 + 0 = 1; rel_idx=0 → abs = base-1-0 = 0
        data = _prefix(2, False, 0) + _dynamic_indexed(0)
        headers = d.decode_field_section(data)
        assert (b"x-test", b"value") in headers

    def test_literal_with_dynamic_name_ref(self):
        d, _ = self._dec_with_entry()
        # Same RIC as above; literal with name from dynamic table
        data = _prefix(2, False, 0) + _literal_name_ref_dynamic(0, b"new-val")
        headers = d.decode_field_section(data)
        assert (b"x-test", b"new-val") in headers

    def test_literal_with_static_name_ref(self):
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(4096))
        # RIC=0 (no dynamic refs in the *body*, only static); static idx 1 = :path
        data = _prefix(0, False, 0) + _literal_name_ref_static(1, b"/api")
        headers = d.decode_field_section(data)
        assert (b":path", b"/api") in headers

    def test_post_base_indexed_field(self):
        d, _ = self._dec_with_entry()
        # Use S=1: base = ric - delta_base - 1 = 1 - 0 - 1 = 0
        # post-base idx 0 → abs = base + 0 = 0
        data = _prefix(2, True, 0) + _post_base_indexed(0)
        headers = d.decode_field_section(data)
        assert (b"x-test", b"value") in headers

    def test_post_base_literal_field(self):
        d, _ = self._dec_with_entry()
        # S=1, base=0; post-base idx 0 → name from abs 0
        data = _prefix(2, True, 0) + _post_base_literal(0, b"pb-value")
        headers = d.decode_field_section(data)
        assert (b"x-test", b"pb-value") in headers

    def test_section_ack_sent_for_dynamic_ref(self):
        d, _ = self._dec_with_entry()
        data = _prefix(2, False, 0) + _dynamic_indexed(0)
        d.decode_field_section(data, stream_id=4)
        instructions = d.flush_decoder_instructions()
        # Section Ack: 1 stream_id[7+] = 0x80 | 4 = 0x84
        assert b"\x84" in instructions

    def test_no_section_ack_for_static_only(self):
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(4096))
        d.flush_decoder_instructions()
        data = _prefix(0, False, 0) + _static_indexed(17)
        d.decode_field_section(data, stream_id=4)
        instructions = d.flush_decoder_instructions()
        # No Section Ack for static-only sections
        assert instructions == b""

    def test_empty_section_returns_empty(self):
        d = QpackDecoder(max_capacity=4096)
        assert d.decode_field_section(b"") == []

    def test_blocked_stream_raises(self):
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(4096))
        # enc_ric=2 claims RIC=1, but table has 0 entries → blocked
        data = _prefix(2, False, 0)
        with pytest.raises(QpackError):
            d.decode_field_section(data)

    def test_ric_encoding_roundtrip_many(self):
        # RFC 9204 §4.5.1.1: verify enc_ric decoding for several insert counts
        max_cap = 4096
        max_entries = max_cap // 32  # 128

        for ric in range(1, max_entries * 2 + 1):
            d = QpackDecoder(max_capacity=max_cap)
            d.feed_encoder_stream(_set_capacity(max_cap))
            for i in range(ric):
                d.feed_encoder_stream(_insert_literal(f"h{i}".encode(), b"v"))
            assert d.table.insert_count == ric

            enc_ric = (ric % (2 * max_entries)) + 1
            # Just decoding the prefix should not raise
            data = _prefix(enc_ric, False, 0)
            d.decode_field_section(data)   # body-less section (no fields after prefix)

    def test_multiple_fields_in_one_section(self):
        d = QpackDecoder(max_capacity=4096)
        d.feed_encoder_stream(_set_capacity(4096))
        data = (
            _prefix(0, False, 0)
            + _static_indexed(17)    # :method GET
            + _static_indexed(1)     # :path /
            + _literal_name(b"x-foo", b"bar")
        )
        headers = d.decode_field_section(data)
        assert len(headers) == 3
        assert (b":method", b"GET") in headers
        assert (b":path", b"/") in headers
        assert (b"x-foo", b"bar") in headers

    def test_null_byte_in_header_value_stripped(self):
        d = QpackDecoder(max_capacity=4096)
        data = _prefix(0, False, 0) + _literal_name(b"x-hdr", b"val\x00ue")
        headers = d.decode_field_section(data)
        # Headers containing NUL bytes must be silently dropped (§4.5.6 + HTTP semantics)
        assert not any(name == b"x-hdr" for name, _ in headers)
