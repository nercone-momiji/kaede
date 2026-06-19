HUFFMANtable: list[tuple[int, int]] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),  # 0, 1, 2, 3
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),  # 4, 5, 6, 7
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),  # 8, 9, 10, 11
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),  # 12, 13, 14, 15
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),  # 16, 17, 18, 19
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),  # 20, 21, 22, 23
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),  # 24, 25, 26, 27
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),  # 28, 29, 30, 31
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),  # 32, 33, 34, 35
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),  # 36, 37, 38, 39
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),  # 40, 41, 42, 43
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),  # 44, 45, 46, 47
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),  # 48, 49, 50, 51
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),  # 52, 53, 54, 55
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),  # 56, 57, 58, 59
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),  # 60, 61, 62, 63
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),  # 64, 65, 66, 67
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),  # 68, 69, 70, 71
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),  # 72, 73, 74, 75
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),  # 76, 77, 78, 79
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),  # 80, 81, 82, 83
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),  # 84, 85, 86, 87
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),  # 88, 89, 90, 91
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),  # 92, 93, 94, 95
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),  # 96, 97, 98, 99
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),  # 100, 101, 102, 103
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),  # 104, 105, 106, 107
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),  # 108, 109, 110, 111
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),  # 112, 113, 114, 115
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),  # 116, 117, 118, 119
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),  # 120, 121, 122, 123
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),  # 124, 125, 126, 127
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),  # 128, 129, 130, 131
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),  # 132, 133, 134, 135
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),  # 136, 137, 138, 139
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),  # 140, 141, 142, 143
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),  # 144, 145, 146, 147
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),  # 148, 149, 150, 151
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),  # 152, 153, 154, 155
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),  # 156, 157, 158, 159
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),  # 160, 161, 162, 163
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),  # 164, 165, 166, 167
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),  # 168, 169, 170, 171
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),  # 172, 173, 174, 175
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),  # 176, 177, 178, 179
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),  # 180, 181, 182, 183
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),  # 184, 185, 186, 187
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),  # 188, 189, 190, 191
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),  # 192, 193, 194, 195
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),  # 196, 197, 198, 199
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),  # 200, 201, 202, 203
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),  # 204, 205, 206, 207
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),  # 208, 209, 210, 211
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),  # 212, 213, 214, 215
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),  # 216, 217, 218, 219
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),  # 220, 221, 222, 223
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),  # 224, 225, 226, 227
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),  # 228, 229, 230, 231
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),  # 232, 233, 234, 235
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),  # 236, 237, 238, 239
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),  # 240, 241, 242, 243
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),  # 244, 245, 246, 247
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),  # 248, 249, 250, 251
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),  # 252, 253, 254, 255
    (0x3fffffff, 30)  # 256 EOS
]

def build_huffman_encodetable() -> dict[int, tuple[int, int]]:
    table: dict[int, tuple[int, int]] = {}
    for sym, (code, bits) in enumerate(HUFFMANtable):
        table[sym] = (code, bits)
    return table

def build_huffman_decodetable() -> dict[tuple[int, int], int]:
    table: dict[tuple[int, int], int] = {}
    for sym, (code, bits) in enumerate(HUFFMANtable):
        table[(code, bits)] = sym
    return table

HUFFMAN_ENCODEtable = build_huffman_encodetable()
HUFFMAN_DECODEtable = build_huffman_decodetable()

def huffman_encode(data: bytes) -> bytes:
    bits = 0
    total_bits = 0

    for byte in data:
        code, length = HUFFMAN_ENCODEtable[byte]
        bits = (bits << length) | code
        total_bits += length

    padding = (8 - total_bits % 8) % 8
    if padding:
        bits = (bits << padding) | ((1 << padding) - 1)
        total_bits += padding

    return bits.to_bytes(total_bits // 8, "big")

def huffman_decode(data: bytes) -> bytes:
    bits = int.from_bytes(data, "big")
    total_bits = len(data) * 8
    out = bytearray()

    current = 0
    current_bits = 0

    for i in range(total_bits - 1, -1, -1):
        bit = (bits >> i) & 1

        current = (current << 1) | bit
        current_bits += 1

        if current_bits > 30:
            raise RuntimeError("code exceeds maximum length")

        sym = HUFFMAN_DECODEtable.get((current, current_bits))

        if sym is not None:
            if sym == 256:
                raise RuntimeError("EOS symbol in Huffman-encoded string is a decoding error (RFC 7541 §5.2)")

            out.append(sym)

            current = 0
            current_bits = 0

    if current_bits >= 8:
        raise RuntimeError("incomplete symbol at end of input")

    if current_bits > 0:
        padding_mask = (1 << current_bits) - 1

        if current != padding_mask:
            raise RuntimeError("invalid padding bits")

    return bytes(out)
