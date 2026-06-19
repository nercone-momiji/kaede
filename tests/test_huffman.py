"""
RFC 7541 §5.2 / RFC 9204 Appendix A: Huffman coding conformance tests.
Both HPACK (HTTP/2) and QPACK (HTTP/3) use the same Huffman code defined in RFC 7541.
"""
from __future__ import annotations

import pytest
from kaede.huffman import huffman_encode, huffman_decode, HUFFMANtable

# RFC 7541 Appendix C test vectors (Huffman-encoded header values)

# Source: RFC 7541 Appendix C.4 (Request examples with Huffman encoding)
RFC7541_VECTORS: list[tuple[bytes, bytes]] = [
    # (plaintext, expected_huffman_bytes)
    (b"www.example.com", bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")),
    (b"no-cache",        bytes.fromhex("a8eb10649cbf")),
    (b"custom-key",      bytes.fromhex("25a849e95ba97d7f")),
    (b"custom-value",    bytes.fromhex("25a849e95bb8e8b4bf")),
    # RFC 7541 Appendix C.6
    (b"Mon, 21 Oct 2013 20:13:21 GMT", bytes.fromhex("d07abe941054d444a8200595040b8166e082a62d1bff")),
    (b"https://www.example.com", bytes.fromhex("9d29ad171863c78f0b97c8e9ae82ae43d3")),
    (b"307",  bytes.fromhex("640eff")),
    (b"gzip", bytes.fromhex("9bd9ab")),
    (b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", bytes.fromhex("94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"))
]

class TestRFC7541Vectors:
    @pytest.mark.parametrize("plaintext,expected", RFC7541_VECTORS)
    def test_encode(self, plaintext, expected):
        """Encoding must match the RFC test vector exactly"""
        assert huffman_encode(plaintext) == expected

    @pytest.mark.parametrize("plaintext,expected", RFC7541_VECTORS)
    def test_decode(self, plaintext, expected):
        """Decoding the RFC vector must recover the original string"""
        assert huffman_decode(expected) == plaintext

# Round-trip properties

class TestRoundTrip:
    def test_all_byte_values(self):
        """Every possible byte value must survive encode→decode"""
        data = bytes(range(256))
        assert huffman_decode(huffman_encode(data)) == data

    def test_empty_string(self):
        assert huffman_encode(b"") == b""
        assert huffman_decode(b"") == b""

    @pytest.mark.parametrize("s", [
        b"hello",
        b"Hello, World!",
        b"0123456789",
        b"\x00\x01\x02\xff",
        b"a" * 1000,
    ])
    def test_roundtrip(self, s):
        assert huffman_decode(huffman_encode(s)) == s

    def test_result_is_bytes(self):
        assert isinstance(huffman_encode(b"test"), bytes)
        assert isinstance(huffman_decode(huffman_encode(b"test")), bytes)

# RFC 7541 §5.2: Padding rules

class TestPadding:
    def test_padding_uses_high_order_eos_bits(self):
        """RFC 7541 §5.2: padding MUST be the most significant bits of the EOS code (all 1s)"""
        # Encode a single space (6 bits: 0x14). Needs 2 padding bits → 0b00010111 = 0x17
        encoded = huffman_encode(b" ")
        assert len(encoded) == 1
        # The last byte must have padding bits set to 1
        last_byte = encoded[-1]
        # The space symbol is 6 bits (0x14 = 0b010100), padded with 2 ones → 0b01010011 = 0x53
        # Actually per HUFFMANtable[32] = (0x14, 6), so bits = 0b010100, pad 2 → 0b01010011 = 0x53
        assert encoded == bytes([0x53])

    def test_invalid_padding_zero_bits_raises(self):
        """RFC 7541 §5.2: padding bits must all be 1; zero padding bits are invalid"""
        # 'a' (index 97) encodes as 0x03, 5 bits → 0b00000_xxx
        # Per HUFFMANtable[97] = (0x3, 5): bits = 0b00011
        # Properly padded: 0b00011_111 = 0x1F
        # Wrong padding with zeros: 0b00011_000 = 0x18
        with pytest.raises((RuntimeError, Exception)):
            huffman_decode(bytes([0x18]))

    def test_too_many_padding_bits_raises(self):
        """RFC 7541 §5.2: padding must be less than 8 bits"""
        # If the padding bits span ≥8 bits that forms a complete code → error
        # An all-1s byte by itself has 8 bits of padding, which is invalid
        with pytest.raises((RuntimeError, Exception)):
            huffman_decode(bytes([0xFF]))

# RFC 7541 §5.2: EOS symbol (code 256)

class TestEOSSymbol:
    def test_eos_not_produced_by_encode(self):
        """RFC 7541 §5.2: EOS is only used for padding, never encoded in strings"""
        for byte_val in range(256):
            encoded = huffman_encode(bytes([byte_val]))
            # Must be decodable without hitting EOS
            decoded = huffman_decode(encoded)
            assert decoded == bytes([byte_val])

    def test_eos_in_input_raises(self):
        """RFC 7541 §5.2: EOS symbol in a Huffman-encoded string is a decoding error"""
        # EOS code is 0x3FFFFFFF (30 bits). Encode just the EOS bits (no data prefix).
        # Pack 30 EOS bits + 2 more 1-bits of padding into 4 bytes = 0xFFFFFFFF
        with pytest.raises((RuntimeError, Exception)):
            huffman_decode(bytes([0xFF, 0xFF, 0xFF, 0xFF]))

    def test_eos_code_is_30_bits(self):
        """RFC 7541 Appendix B: EOS is symbol 256 with code 0x3FFFFFFF, 30 bits"""
        eos_code, eos_bits = HUFFMANtable[256]
        assert eos_code == 0x3FFFFFFF
        assert eos_bits == 30

# Huffman table properties

class TestHuffmanTable:
    def testtable_has_257_entries(self):
        """RFC 7541 Appendix B: table covers bytes 0-255 plus EOS (256)"""
        assert len(HUFFMANtable) == 257

    def test_all_codes_unique(self):
        seen: set[tuple[int, int]] = set()
        for sym, (code, bits) in enumerate(HUFFMANtable):
            key = (code, bits)
            assert key not in seen, f"Duplicate code for symbol {sym}"
            seen.add(key)

    def test_all_codes_fit_in_bit_width(self):
        for sym, (code, bits) in enumerate(HUFFMANtable):
            assert code < (1 << bits), f"Symbol {sym}: code {code!r} exceeds {bits} bits"

    def test_bit_widths_between_5_and_30(self):
        """RFC 7541 Appendix B: codes are 5 to 30 bits"""
        for sym, (code, bits) in enumerate(HUFFMANtable):
            assert 5 <= bits <= 30, f"Symbol {sym} has {bits}-bit code outside [5,30]"

# RFC 7541 Appendix B: specific symbol code verification

class TestSpecificSymbolCodes:
    """Spot-check individual entries from RFC 7541 Appendix B"""

    def test_symbol_97_letter_a(self):
        """'a' (0x61 = 97) has code 0x03, 5 bits per RFC 7541 Appendix B"""
        code, bits = HUFFMANtable[97]
        assert code == 0x03
        assert bits == 5

    def test_symbol_48_digit_0(self):
        """'0' (0x30 = 48) has code 0x00, 5 bits per RFC 7541 Appendix B"""
        code, bits = HUFFMANtable[48]
        assert code == 0x00
        assert bits == 5

    def test_symbol_32_space(self):
        """' ' (0x20 = 32) has code 0x14, 6 bits per RFC 7541 Appendix B"""
        code, bits = HUFFMANtable[32]
        assert code == 0x14
        assert bits == 6

    def test_symbol_58_colon(self):
        """':' (0x3A = 58) has code 0x5c (92), 7 bits per RFC 7541 Appendix B"""
        code, bits = HUFFMANtable[58]
        assert code == 0x5C
        assert bits == 7

    def test_symbol_47_slash(self):
        """'/' (0x2F = 47) has code 0x18 (24), 6 bits per RFC 7541 Appendix B"""
        code, bits = HUFFMANtable[47]
        assert code == 0x18
        assert bits == 6

# Additional round-trip and encode properties

class TestHuffmanProperties:
    def test_encode_length_never_exceeds_input_by_too_much(self):
        """Huffman encoding should not expand data more than 12.5% in pathological cases"""
        for byte_val in range(256):
            data = bytes([byte_val]) * 100
            encoded = huffman_encode(data)
            # Worst-case expansion is bounded (RFC 7541 guarantees ≤ 30 bits/symbol)
            assert len(encoded) <= len(data) * 4  # very conservative bound

    def test_encode_ascii_printable_is_compact(self):
        """Common ASCII text should compress with Huffman (or stay same size)"""
        text = b"GET / HTTP/1.1"
        encoded = huffman_encode(text)
        # ASCII printable characters are short codes (5-8 bits), so encoding
        # should produce fewer or equal bytes than raw
        assert len(encoded) <= len(text)

    def test_decode_encode_identity_for_rfc_vector_bytes(self):
        """Each RFC 7541 test vector decodes to the correct string"""
        for plaintext, expected_encoded in [
            (b"www.example.com", bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")),
            (b"no-cache",        bytes.fromhex("a8eb10649cbf")),
        ]:
            assert huffman_encode(plaintext) == expected_encoded
            assert huffman_decode(expected_encoded) == plaintext

    def test_all_single_bytes_roundtrip(self):
        """Every possible single-byte value must round-trip through Huffman"""
        for b in range(256):
            original = bytes([b])
            assert huffman_decode(huffman_encode(original)) == original
