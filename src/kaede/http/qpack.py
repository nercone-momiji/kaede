from __future__ import annotations

from ..huffman import huffman_decode

# ---------------------------------------------------------------------------
# QPACK Dynamic Table (RFC 9204 §3.2)
# ---------------------------------------------------------------------------

class DynamicTable:
    """QPACK dynamic table – absolute-indexed, FIFO eviction (RFC 9204 §3.2)."""

    OVERHEAD = 32  # per-entry overhead in bytes (§3.2.1)

    def __init__(self, capacity: int = 0):
        self._capacity = capacity
        self._used = 0
        self._entries: list[tuple[bytes, bytes]] = []  # oldest first
        self._base = 0  # absolute index of _entries[0]

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def insert_count(self) -> int:
        return self._base + len(self._entries)

    @property
    def max_entries(self) -> int:
        """MaxEntries = floor(capacity / 32) used for RIC mod-encoding (§4.5.1.1)."""
        return self._capacity // self.OVERHEAD

    @staticmethod
    def _entry_size(name: bytes, value: bytes) -> int:
        return len(name) + len(value) + DynamicTable.OVERHEAD

    def set_capacity(self, cap: int) -> None:
        self._capacity = cap
        self._evict()

    def _evict(self) -> None:
        while self._used > self._capacity and self._entries:
            n, v = self._entries.pop(0)
            self._used -= self._entry_size(n, v)
            self._base += 1

    def insert(self, name: bytes, value: bytes) -> int:
        """Insert an entry; evict oldest entries as needed. Returns absolute index."""
        sz = self._entry_size(name, value)
        if sz > self._capacity:
            raise QpackError(f"dynamic table entry ({sz} bytes) exceeds capacity ({self._capacity})")
        while self._used + sz > self._capacity and self._entries:
            n, v = self._entries.pop(0)
            self._used -= self._entry_size(n, v)
            self._base += 1
        self._entries.append((name, value))
        self._used += sz
        return self._base + len(self._entries) - 1

    def get(self, absolute: int) -> tuple[bytes, bytes]:
        """Return the entry at the given absolute index or raise QpackError."""
        rel = absolute - self._base
        if rel < 0 or rel >= len(self._entries):
            raise QpackError(f"dynamic table entry {absolute} not available (evicted or not yet inserted)")
        return self._entries[rel]


class QpackDecoder:
    """Decoder-side QPACK state machine (RFC 9204).

    Processes instructions received on the peer's encoder stream (stream type
    0x02) and decodes field sections that may reference the dynamic table.
    Produces decoder-stream instructions (Insert Count Increment, Section
    Acknowledgment) to send back to the peer.
    """

    DEFAULT_CAPACITY = 4096

    def __init__(self, max_capacity: int = DEFAULT_CAPACITY):
        self._max_capacity = max_capacity
        self._table = DynamicTable(capacity=0)
        self._enc_buf: bytearray = bytearray()     # encoder stream receive buffer
        self._dec_pending: bytearray = bytearray() # decoder stream instructions to send
        self._ici_pending: int = 0                 # Insert Count Increments to send

    @property
    def insert_count(self) -> int:
        return self._table.insert_count

    @property
    def max_table_capacity(self) -> int:
        return self._max_capacity

    # ------------------------------------------------------------------
    # Encoder stream (RFC 9204 §3.2)
    # ------------------------------------------------------------------

    def feed_encoder_stream(self, data: bytes) -> None:
        """Process bytes received on the peer's encoder stream (type 0x02)."""
        self._enc_buf.extend(data)
        buf = bytes(self._enc_buf)
        pos = 0
        inserted = 0

        while pos < len(buf):
            first = buf[pos]

            if first & 0x80:
                # Insert with Name Reference (§3.2.3): 1T idx[6+] value
                is_static = bool(first & 0x40)
                try:
                    idx, pos = decode_integer(buf, pos, 6)
                    value, pos = decode_string(buf, pos, 7)
                except QpackError:
                    break  # incomplete instruction; wait for more data

                if is_static:
                    if idx >= len(STATIC_TABLE):
                        raise QpackError(f"encoder stream: static index {idx} out of range")
                    name = STATIC_TABLE[idx][0]
                else:
                    abs_idx = self._table.insert_count - 1 - idx
                    name = self._table.get(abs_idx)[0]

                self._table.insert(name, value)
                inserted += 1

            elif first & 0x40:
                # Insert with Literal Name (§3.2.4): 01H name[5+] value[7+]
                try:
                    name, pos = decode_string(buf, pos, 5)
                    value, pos = decode_string(buf, pos, 7)
                except QpackError:
                    break

                self._table.insert(name.lower(), value)
                inserted += 1

            elif first & 0x20:
                # Set Dynamic Table Capacity (§3.2.1): 001 cap[5+]
                try:
                    cap, pos = decode_integer(buf, pos, 5)
                except QpackError:
                    break

                if cap > self._max_capacity:
                    raise QpackError(f"encoder requested capacity {cap} > our max {self._max_capacity}")
                self._table.set_capacity(cap)

            else:
                # Duplicate (§3.2.5): 000 idx[5+]
                try:
                    idx, pos = decode_integer(buf, pos, 5)
                except QpackError:
                    break

                abs_idx = self._table.insert_count - 1 - idx
                entry = self._table.get(abs_idx)
                self._table.insert(entry[0], entry[1])
                inserted += 1

        del self._enc_buf[:pos]
        if inserted > 0:
            self._ici_pending += inserted

    # ------------------------------------------------------------------
    # Field section decoding (RFC 9204 §4.5)
    # ------------------------------------------------------------------

    def decode_field_section(self, data: bytes, stream_id: int | None = None) -> list[tuple[bytes, bytes]]:
        """Decode a HEADERS field section that may reference the dynamic table.

        Sends a Section Acknowledgment on the decoder stream when *stream_id* is
        given and the section contains dynamic table references (§4.4.1).
        Raises *QpackError* on malformed input or blocked streams.
        """
        if not data:
            return []

        offset = 0
        enc_ric, offset = decode_integer(data, offset, 8)

        if offset >= len(data):
            raise QpackError("field section prefix too short")
        s_bit = bool(data[offset] & 0x80)
        delta_base, offset = decode_integer(data, offset, 7)

        # Decode Required Insert Count (§4.5.1.1)
        if enc_ric == 0:
            ric = 0
        else:
            max_entries = self._table.max_entries
            if max_entries == 0:
                raise QpackError("dynamic reference in field section but table capacity is 0")
            full_range = 2 * max_entries
            if enc_ric > full_range:
                raise QpackError("encoded Required Insert Count out of range")
            total = self._table.insert_count
            max_value = total + max_entries
            max_wrapped = (max_value // full_range) * full_range
            ric = max_wrapped + enc_ric - 1
            if ric > max_value:
                ric -= full_range
            if ric == 0 or ric > max_value:
                raise QpackError("invalid Required Insert Count after decoding")

        if ric > self._table.insert_count:
            raise QpackError(f"QPACK blocked stream: RIC={ric} > insert_count={self._table.insert_count}")

        # Base (§4.5.1.2)
        if s_bit:
            base = ric - delta_base - 1
        else:
            base = ric + delta_base

        has_dynamic_ref = False
        headers: list[tuple[bytes, bytes]] = []
        n = len(data)

        while offset < n:
            first = data[offset]

            if first & 0x80:
                # Indexed Field Line (§4.5.2): 1T idx[6+]
                is_static = bool(first & 0x40)
                idx, offset = decode_integer(data, offset, 6)
                if is_static:
                    if idx >= len(STATIC_TABLE):
                        raise QpackError(f"static index {idx} out of range")
                    headers.append(STATIC_TABLE[idx])
                else:
                    abs_idx = base - 1 - idx
                    headers.append(self._table.get(abs_idx))
                    has_dynamic_ref = True

            elif first & 0x40:
                # Literal Field Line with Name Reference (§4.5.4): 01NT idx[4+] value
                is_static = bool(first & 0x10)
                idx, offset = decode_integer(data, offset, 4)
                value, offset = decode_string(data, offset, 7)
                if is_static:
                    if idx >= len(STATIC_TABLE):
                        raise QpackError(f"static name-ref index {idx} out of range")
                    name = STATIC_TABLE[idx][0]
                else:
                    abs_idx = base - 1 - idx
                    name = self._table.get(abs_idx)[0]
                    has_dynamic_ref = True
                headers.append((name, value))

            elif first & 0x20:
                # Literal Field Line with Literal Name (§4.5.6): 001NH name[3+] value
                name, offset = decode_string(data, offset, 3)
                value, offset = decode_string(data, offset, 7)
                headers.append((name.lower(), value))

            elif first & 0x10:
                # Indexed Field Line with Post-Base Index (§4.5.3): 0001 idx[4+]
                idx, offset = decode_integer(data, offset, 4)
                abs_idx = base + idx
                headers.append(self._table.get(abs_idx))
                has_dynamic_ref = True

            else:
                # Literal Field Line with Post-Base Name Reference (§4.5.5): 0000N idx[3+] value
                idx, offset = decode_integer(data, offset, 3)
                value, offset = decode_string(data, offset, 7)
                abs_idx = base + idx
                name = self._table.get(abs_idx)[0]
                has_dynamic_ref = True
                headers.append((name, value))

        if has_dynamic_ref and stream_id is not None:
            # Section Acknowledgment (§4.4.1): 1 stream_id[7+]
            self._dec_pending += encode_integer(stream_id, 7, 0x80)

        return [
            (name, value) for name, value in headers
            if b"\r" not in name and b"\n" not in name and b"\x00" not in name
            and b"\r" not in value and b"\n" not in value and b"\x00" not in value
        ]

    # ------------------------------------------------------------------
    # Decoder stream output (RFC 9204 §4.4)
    # ------------------------------------------------------------------

    def flush_decoder_instructions(self) -> bytes:
        """Return any pending decoder-stream instructions to send."""
        out = bytearray()
        if self._ici_pending > 0:
            # Insert Count Increment (§4.4.3): 00 increment[6+]
            out += encode_integer(self._ici_pending, 6, 0x00)
            self._ici_pending = 0
        out += self._dec_pending
        self._dec_pending = bytearray()
        return bytes(out)

STATIC_TABLE: list[tuple[bytes, bytes]] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin")
]

STATIC_INDEX_BY_HEADER: dict[tuple[bytes, bytes], int] = {}
STATIC_INDEX_BY_NAME: dict[bytes, int] = {}

for _i, (_n, _v) in enumerate(STATIC_TABLE):
    STATIC_INDEX_BY_HEADER.setdefault((_n, _v), _i)
    STATIC_INDEX_BY_NAME.setdefault(_n, _i)

SENSITIVE_HEADERS: frozenset[bytes] = frozenset([
    b"authorization",
    b"cookie",
    b"set-cookie",
    b"www-authenticate",
    b"proxy-authenticate",
    b"proxy-authorization"
])

class QpackError(Exception):
    pass

def encode_integer(value: int, prefix_bits: int, flags: int = 0) -> bytes:
    mask = (1 << prefix_bits) - 1
    out = bytearray()

    if value < mask:
        out.append(flags | value)
        return bytes(out)

    out.append(flags | mask)

    value -= mask

    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7

    out.append(value)
    return bytes(out)

def decode_integer(data: bytes, offset: int, prefix_bits: int) -> tuple[int, int]:
    mask = (1 << prefix_bits) - 1
    value = data[offset] & mask

    offset += 1

    if value < mask:
        return value, offset

    shift = 0

    for _ in range(10):
        if offset >= len(data):
            raise QpackError("integer encoding truncated")
        b = data[offset]
        offset += 1
        value += (b & 0x7F) << shift
        shift += 7

        if not (b & 0x80):
            break
    else:
        raise QpackError("integer encoding too long")

    return value, offset

def encode_string(value: bytes, prefix_bits: int, flag_bit: int) -> bytes:
    out = bytearray()
    out += encode_integer(len(value), prefix_bits, flag_bit)
    out += value
    return bytes(out)

def decode_string(data: bytes, offset: int, prefix_bits: int) -> tuple[bytes, int]:
    huffman = bool(data[offset] & (1 << prefix_bits))
    length, offset = decode_integer(data, offset, prefix_bits)
    raw = data[offset:offset + length]
    offset += length

    if huffman:
        raw = huffman_decode(raw)

    return raw, offset

def encode_headers(headers: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray()
    out += encode_integer(0, 8)
    out += encode_integer(0, 7)

    for name, value in headers:
        name = name.lower()
        sensitive = name in SENSITIVE_HEADERS

        if sensitive:
            name_idx = STATIC_INDEX_BY_NAME.get(name)
            if name_idx is not None:
                flag = 0x70 if sensitive else 0x50
                out += encode_integer(name_idx, 4, flag)
                out += encode_string(value, 7, 0)
            else:
                flag = 0x30 if sensitive else 0x20
                out += encode_string(name, 3, flag)
                out += encode_string(value, 7, 0)
            continue

        full = STATIC_INDEX_BY_HEADER.get((name, value))
        if full is not None:
            out += encode_integer(full, 6, 0xC0)
            continue

        name_idx = STATIC_INDEX_BY_NAME.get(name)
        if name_idx is not None:
            out += encode_integer(name_idx, 4, 0x50)
            out += encode_string(value, 7, 0)
        else:
            out += encode_string(name, 3, 0x20)
            out += encode_string(value, 7, 0)

    return bytes(out)

def decode_headers(data: bytes) -> list[tuple[bytes, bytes]]:
    """Decode a QPACK-encoded field section using the static table only.

    Rejects any dynamic-table reference (Required Insert Count != 0 or dynamic
    indexed/name-reference representations).  Use *QpackDecoder.decode_field_section*
    when dynamic-table support is required.
    """
    offset = 0
    required_insert_count, offset = decode_integer(data, offset, 8)

    if offset >= len(data):
        return []
    delta_base, offset = decode_integer(data, offset, 7)

    if required_insert_count != 0:
        raise QpackError("dynamic table references are not supported (QPACK capacity is 0)")

    headers: list[tuple[bytes, bytes]] = []
    n = len(data)

    while offset < n:
        first = data[offset]
        if first & 0x80:
            is_static = bool(first & 0x40)
            index, offset = decode_integer(data, offset, 6)

            if not is_static:
                raise QpackError("dynamic table reference not supported")

            if index >= len(STATIC_TABLE):
                raise QpackError(f"static table index out of range: {index}")
            headers.append(STATIC_TABLE[index])

        elif first & 0x40:
            is_static = bool(first & 0x10)
            index, offset = decode_integer(data, offset, 4)

            if not is_static:
                raise QpackError("dynamic table reference not supported")

            if index >= len(STATIC_TABLE):
                raise QpackError(f"static table index out of range: {index}")
            name = STATIC_TABLE[index][0]
            value, offset = decode_string(data, offset, 7)
            headers.append((name, value))

        elif first & 0x20:
            name, offset = decode_string(data, offset, 3)
            value, offset = decode_string(data, offset, 7)
            headers.append((name.lower(), value))

        else:
            raise QpackError(f"unsupported QPACK representation 0x{first:02x}")

    return [(name, value) for name, value in headers if b"\r" not in name and b"\n" not in name and b"\x00" not in name and b"\r" not in value and b"\n" not in value and b"\x00" not in value]
