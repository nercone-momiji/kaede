from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

LEVEL_INITIAL = 0
LEVEL_EARLY = 1
LEVEL_HANDSHAKE = 2
LEVEL_APPLICATION = 3

INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_CIPHER = "TLS_AES_128_GCM_SHA256"

AEAD_TAG_SIZE = 16

RETRY_INTEGRITY_SECRET = bytes.fromhex("d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876d9fb057")

@dataclass
class Suite:
    name: str
    key_len: int
    algorithm: hashes.HashAlgorithm
    is_chacha: bool

def hash_for(name: str) -> hashes.HashAlgorithm:
    return hashes.SHA384() if name == "TLS_AES_256_GCM_SHA384" else hashes.SHA256()

def hkdf_extract(salt: bytes, ikm: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    h = hmac.HMAC(salt, algorithm)
    h.update(ikm)
    return h.finalize()

def hkdf_expand_label(secret: bytes, label: bytes, length: int, algorithm: hashes.HashAlgorithm, context: bytes = b"") -> bytes:
    full_label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return HKDFExpand(algorithm=algorithm, length=length, info=info).derive(secret)

def suite_for(cipher_name: str) -> Suite:
    if cipher_name == "TLS_AES_256_GCM_SHA384":
        return Suite(cipher_name, 32, hashes.SHA384(), False)
    if cipher_name == "TLS_CHACHA20_POLY1305_SHA256":
        return Suite(cipher_name, 32, hashes.SHA256(), True)
    return Suite(INITIAL_CIPHER, 16, hashes.SHA256(), False)

class HeaderProtection:
    def __init__(self, hp_key: bytes, is_chacha: bool):
        self.hp_key = hp_key
        self.is_chacha = is_chacha

    def mask(self, sample: bytes) -> bytes:
        if self.is_chacha:
            cipher = Cipher(algorithms.ChaCha20(self.hp_key, sample), mode=None)
            return cipher.encryptor().update(b"\x00\x00\x00\x00\x00")

        encryptor = Cipher(algorithms.AES(self.hp_key), modes.ECB()).encryptor()
        return (encryptor.update(sample) + encryptor.finalize())[:5]

class PacketKeys:
    def __init__(self, secret: bytes, suite: Suite, hp: "HeaderProtection | None" = None):
        self.suite = suite
        self.secret = secret
        self.key = hkdf_expand_label(secret, b"quic key", suite.key_len, suite.algorithm)
        self.iv = hkdf_expand_label(secret, b"quic iv", 12, suite.algorithm)

        # RFC 9001 §6.1: a key update does not change the header protection key,
        # so it can be carried over from the prior generation when provided.
        if hp is not None:
            self.hp = hp
        else:
            hp_key = hkdf_expand_label(secret, b"quic hp", suite.key_len, suite.algorithm)
            self.hp = HeaderProtection(hp_key, suite.is_chacha)

        self.aead = ChaCha20Poly1305(self.key) if suite.is_chacha else AESGCM(self.key)

    def next_generation(self) -> "PacketKeys":
        # RFC 9001 §6.1: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
        new_secret = hkdf_expand_label(self.secret, b"quic ku", self.suite.algorithm.digest_size, self.suite.algorithm)
        return PacketKeys(new_secret, self.suite, hp=self.hp)

    def nonce(self, packet_number: int) -> bytes:
        pn = packet_number.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.iv, pn))

    def encrypt(self, packet_number: int, header: bytes, plaintext: bytes) -> bytes:
        return self.aead.encrypt(self.nonce(packet_number), plaintext, header)

    def decrypt(self, packet_number: int, header: bytes, ciphertext: bytes) -> bytes:
        return self.aead.decrypt(self.nonce(packet_number), ciphertext, header)

def initial_secret(destination_connection_id: bytes) -> bytes:
    return hkdf_extract(INITIAL_SALT_V1, destination_connection_id, hashes.SHA256())

def initial_keys(destination_connection_id: bytes) -> tuple[PacketKeys, PacketKeys]:
    suite = suite_for(INITIAL_CIPHER)
    secret = initial_secret(destination_connection_id)

    client_secret = hkdf_expand_label(secret, b"client in", suite.algorithm.digest_size, suite.algorithm)
    server_secret = hkdf_expand_label(secret, b"server in", suite.algorithm.digest_size, suite.algorithm)

    return PacketKeys(client_secret, suite), PacketKeys(server_secret, suite)

def verify_retry_integrity_tag(pseudo_packet: bytes, tag: bytes) -> bool:
    algo = hashes.SHA256()
    key = hkdf_expand_label(RETRY_INTEGRITY_SECRET, b"quic retry integrity", 16, algo)
    nonce = hkdf_expand_label(RETRY_INTEGRITY_SECRET, b"quic retry integrity nonce", 12, algo)
    expected = AESGCM(key).encrypt(nonce, b"", pseudo_packet)
    return expected == tag
