import io
import random
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from chunkseal import (
    AuthenticationError, BytesSource, FileSource, FormatError, MAX_CHUNKS,
    Reader, decrypt_stream, derive_key, encrypt_bytes, encrypt_stream, parse_header,
)
from chunkseal.core import _encrypt_stream

ROOT = Path(__file__).resolve().parents[1]


def properties():
    values = {}
    for line in (ROOT / "test-vectors/v1.properties").read_text("ascii").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def synthetic_header(*, size=0, log2=12):
    return struct.pack("<4sBBBBIHH16s8sQ16s", b"CSEA", 1, 0, log2, 1, 1000,
                       0, 0, bytes(16), bytes(8), size, bytes(16))


class ProtocolTests(unittest.TestCase):
    def make_container(self, *, metadata=None, size=3 * 4096 + 31):
        plain = bytes((index * 37 + 19) & 255 for index in range(size))
        cipher = encrypt_bytes(plain, "test-password", metadata=metadata,
                               chunk_log2=12, rounds=1000, key_id=7)
        return plain, cipher

    def test_frozen_known_answer_vectors(self):
        values = properties()
        for name in values["vectors"].split(","):
            with self.subTest(vector=name):
                get = lambda field: values[f"{name}.{field}"]
                password = bytes.fromhex(get("password_utf8_hex")).decode("utf-8")
                plain = bytes.fromhex(get("plaintext_hex"))
                metadata = None if get("metadata_hex") == "-" else bytes.fromhex(get("metadata_hex"))
                salt = bytes.fromhex(get("salt_hex"))
                prefix = bytes.fromhex(get("nonce_prefix_hex"))
                rounds, log2, key_id = (int(get(field)) for field in ("rounds", "chunk_log2", "key_id"))
                self.assertEqual(derive_key(password, salt, rounds).hex(), get("key_hex"))
                destination = io.BytesIO()
                _encrypt_stream(io.BytesIO(plain), destination, len(plain), password,
                                metadata=metadata, chunk_log2=log2, rounds=rounds,
                                key_id=key_id, salt=salt, nonce_prefix=prefix)
                self.assertEqual(destination.getvalue().hex(), get("container_hex"))
                self.assertEqual(destination.getvalue()[:64].hex(), get("header_hex"))
                reader = Reader(BytesSource(bytes.fromhex(get("container_hex"))), password)
                self.assertEqual(reader.read(0, len(plain)), plain)
                self.assertEqual(reader.metadata(), metadata)
                self.assertEqual(reader.header.key_id, key_id)

    def test_random_and_cross_boundary_ranges(self):
        plain, cipher = self.make_container()
        reader = Reader(BytesSource(cipher), "test-password")
        generator = random.Random(42)
        for _ in range(150):
            start = generator.randrange(len(plain) + 1)
            length = generator.randrange(len(plain) - start + 1)
            self.assertEqual(reader.read(start, length), plain[start:start + length])
        self.assertEqual(reader.read(4090, 20), plain[4090:4110])
        self.assertEqual(reader.read(len(plain), 0), b"")

    def test_seeking_fetches_only_required_records(self):
        plain, cipher = self.make_container(metadata=b"metadata")

        class RecordingSource(BytesSource):
            def __init__(self, data):
                super().__init__(data)
                self.requests = []

            def read_at(self, offset, length):
                self.requests.append((offset, length))
                return super().read_at(offset, length)

        source = RecordingSource(cipher)
        reader = Reader(source, "test-password")
        source.requests.clear()
        self.assertEqual(reader.read(4090, 20), plain[4090:4110])
        base = 64 + reader.header.metadata_size
        self.assertEqual(source.requests, [(base, 4112), (base + 4112, 4112)])
        source.requests.clear()
        self.assertEqual(reader.read(len(plain), 0), b"")
        self.assertEqual(source.requests, [])

    def test_metadata_is_opaque_bytes(self):
        _, cipher = self.make_container(metadata=bytes(range(256)))
        self.assertEqual(Reader(BytesSource(cipher), "test-password").metadata(), bytes(range(256)))

    def test_empty_metadata_and_absence_are_distinct(self):
        for metadata, flags, encoded_length in ((None, 0, 0), (b"", 1, 16)):
            _, cipher = self.make_container(metadata=metadata, size=0)
            reader = Reader(BytesSource(cipher), "test-password")
            self.assertEqual(reader.metadata(), metadata)
            self.assertEqual(reader.header.flags, flags)
            self.assertEqual(reader.header.metadata_size, encoded_length)
            self.assertEqual(reader.read(0, 0), b"")
            self.assertEqual(len(cipher), 64 + encoded_length)

    def test_wrong_password_and_changed_header_fail_authentication(self):
        _, cipher = self.make_container()
        with self.assertRaises(AuthenticationError):
            Reader(BytesSource(cipher), "wrong-password")
        for offset in (14, 32, 48):
            changed = bytearray(cipher)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(AuthenticationError):
                Reader(BytesSource(changed), "test-password")

    def test_changed_data_and_metadata_fail_before_returning_plaintext(self):
        _, cipher = self.make_container(metadata=b"metadata")
        for target in ("metadata", "data"):
            changed = bytearray(cipher)
            header = parse_header(cipher[:64])
            changed[64 if target == "metadata" else header.chunk_offset(0)] ^= 1
            reader = Reader(BytesSource(changed), "test-password")
            with self.subTest(target=target), self.assertRaises(AuthenticationError):
                reader.metadata() if target == "metadata" else reader.read_chunk(0)

    def test_unread_records_are_not_claimed_to_be_authenticated(self):
        plain, cipher = self.make_container()
        changed = bytearray(cipher)
        header = parse_header(cipher[:64])
        changed[header.chunk_offset(2)] ^= 1
        reader = Reader(BytesSource(changed), "test-password")
        self.assertEqual(reader.read(0, 20), plain[:20])
        with self.assertRaises(AuthenticationError):
            decrypt_stream(reader, io.BytesIO())

    def test_swapping_records_fails_authentication(self):
        _, cipher = self.make_container(size=3 * 4096)
        changed = bytearray(cipher)
        first = cipher[64:64 + 4112]
        second = cipher[64 + 4112:64 + 8224]
        changed[64:64 + 4112] = second
        changed[64 + 4112:64 + 8224] = first
        reader = Reader(BytesSource(changed), "test-password")
        with self.assertRaises(AuthenticationError):
            reader.read_chunk(0)

    def test_truncated_and_overlong_containers_are_rejected(self):
        _, cipher = self.make_container(metadata=b"x")
        for data in (cipher[:63], cipher[:64], cipher[:-1], cipher + b"x"):
            with self.subTest(size=len(data)), self.assertRaises(FormatError):
                Reader(BytesSource(data), "test-password")

    def test_short_byte_range_response_is_rejected(self):
        _, cipher = self.make_container()

        class ShortRange(BytesSource):
            def read_at(self, offset, length):
                data = super().read_at(offset, length)
                return data if offset == 0 else data[:-1]

        reader = Reader(ShortRange(cipher), "test-password")
        with self.assertRaises(FormatError):
            reader.read_chunk(0)

    def test_malformed_fields_are_rejected(self):
        changes = (
            (0, b"XXXX"), (4, b"\x02"), (5, b"\x02"), (6, b"\x0b"),
            (6, b"\x1b"), (7, b"\x02"), (8, bytes(4)),
            (8, struct.pack("<I", 0x80000000)), (12, b"\x10\x00"),
            (40, struct.pack("<Q", (1 << 64) - 1)),
        )
        for offset, replacement in changes:
            header = bytearray(synthetic_header())
            header[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset, replacement=replacement), self.assertRaises(FormatError):
                parse_header(bytes(header))
        header = bytearray(synthetic_header())
        header[5] = 1
        with self.assertRaises(FormatError):
            parse_header(bytes(header))

    def test_nonce_counter_and_64_bit_offset_boundaries(self):
        size = (1 << 33) + 12345
        header = parse_header(synthetic_header(size=size, log2=20))
        self.assertEqual(header.chunk_count, 8193)
        self.assertGreater(header.chunk_offset(4096), (1 << 31) - 1)
        limit = MAX_CHUNKS * 4096
        header = parse_header(synthetic_header(size=limit))
        self.assertEqual(header.chunk_count, MAX_CHUNKS)
        header.chunk_offset(MAX_CHUNKS - 1)
        with self.assertRaises(FormatError):
            header.chunk_offset(MAX_CHUNKS)
        with self.assertRaises(FormatError):
            parse_header(synthetic_header(size=limit + 1))

    def test_range_bounds(self):
        plain, cipher = self.make_container()
        reader = Reader(BytesSource(cipher), "test-password")
        for offset, length in ((-1, 1), (0, -1), (len(plain), 1), (1 << 63, 1)):
            with self.subTest(offset=offset, length=length), self.assertRaises(FormatError):
                reader.read(offset, length)

    def test_reader_kdf_policy_is_checked_before_derivation(self):
        header = bytearray(synthetic_header())
        struct.pack_into("<I", header, 8, 6_000_000)
        with patch("chunkseal.core.derive_key", side_effect=AssertionError("KDF must not run")):
            with self.assertRaisesRegex(FormatError, "policy"):
                Reader(BytesSource(header), "password")
        cipher = encrypt_bytes(b"x", "password", rounds=3000)
        with self.assertRaises(FormatError):
            Reader(BytesSource(cipher), "password", max_rounds=2000)
        self.assertEqual(Reader(BytesSource(cipher), "password", max_rounds=4000).read(0, 1), b"x")

    def test_metadata_length_limit(self):
        cipher = encrypt_bytes(b"", "password", metadata=bytes(65519), rounds=1000)
        self.assertEqual(len(Reader(BytesSource(cipher), "password").metadata()), 65519)
        with self.assertRaises(FormatError):
            encrypt_bytes(b"", "password", metadata=bytes(65520), rounds=1000)

    def test_streaming_short_reads_and_short_writes(self):
        plain = bytes(range(256)) * 35

        class ShortReads(io.BytesIO):
            def read(self, length=-1):
                return super().read(min(length, 37) if length >= 0 else 37)

        class ShortWrites(io.BytesIO):
            def write(self, data):
                return super().write(data[:9])

        destination = ShortWrites()
        encrypt_stream(ShortReads(plain), destination, len(plain), "password",
                       chunk_log2=12, rounds=1000)
        result = io.BytesIO()
        decrypt_stream(Reader(FileSource(io.BytesIO(destination.getvalue())), "password"), result)
        self.assertEqual(result.getvalue(), plain)

    def test_declared_input_size_must_match_stream(self):
        for declared_size in (0, 2):
            with self.assertRaises(FormatError):
                encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), declared_size, "password", rounds=1000)

    def test_passwords_are_strict_utf8_without_normalization(self):
        self.assertNotEqual(derive_key("é", bytes(16), 1000),
                            derive_key("e\u0301", bytes(16), 1000))
        with self.assertRaises(FormatError):
            derive_key("\ud800", bytes(16), 1000)

    def test_default_writer_uses_fresh_salt_and_nonce(self):
        first = encrypt_bytes(b"x", "password")
        second = encrypt_bytes(b"x", "password")
        header = parse_header(first[:64])
        self.assertEqual(header.rounds, 600_000)
        self.assertEqual(header.chunk_log2, 20)
        self.assertNotEqual(first[16:32], second[16:32])
        self.assertNotEqual(first[32:40], second[32:40])
        self.assertEqual(Reader(BytesSource(first), "password").read(0, 1), b"x")


if __name__ == "__main__":
    unittest.main()
