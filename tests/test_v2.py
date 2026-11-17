import io
import random
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from chunkseal import (
    AuthenticationError, BytesSource, FileSource, FormatError, MAX_CHUNKS,
    Reader, encrypt_bytes, open_reader,
)
from chunkseal import v2

ROOT = Path(__file__).resolve().parents[1]
KEY = bytes(range(0x20, 0x40))


def properties():
    values = {}
    for line in (ROOT / "test-vectors/v2.properties").read_text("ascii").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def synthetic_header(*, size=0, log2=12, kdf=2, rounds=0):
    return struct.pack("<4sBBBBIHH16s8sQ16s", b"CSEA", 2, 0, log2, kdf, rounds,
                       0, 0, bytes(16), bytes(8), size, bytes(16))


class V2Tests(unittest.TestCase):
    def make_container(self, *, metadata=None, size=3 * 4096 + 31, password=None):
        plain = bytes((index * 37 + 19) & 255 for index in range(size))
        secret = {"password": password, "rounds": 1000} if password is not None \
            else {"master_key": KEY}
        cipher = v2.encrypt_bytes(plain, metadata=metadata, chunk_log2=12, key_id=7, **secret)
        return plain, cipher

    def open(self, cipher, password=None):
        secret = {"password": password} if password is not None else {"master_key": KEY}
        return v2.Reader(BytesSource(cipher), **secret)

    def test_frozen_known_answer_vectors(self):
        values = properties()
        for name in values["vectors"].split(","):
            with self.subTest(vector=name):
                get = lambda field: values[f"{name}.{field}"]
                plain = bytes.fromhex(get("plaintext_hex"))
                metadata = None if get("metadata_hex") == "-" else bytes.fromhex(get("metadata_hex"))
                log2, key_id = int(get("chunk_log2")), int(get("key_id"))
                salt = bytes.fromhex(get("salt_hex"))
                prefix = bytes.fromhex(get("nonce_prefix_hex"))
                if get("kdf_id") == "2":
                    key = bytes.fromhex(get("master_key_hex"))
                    deterministic = dict(master_key=key, password=None, rounds=0)
                    secret = dict(master_key=key)
                else:
                    password = bytes.fromhex(get("password_utf8_hex")).decode("utf-8")
                    rounds = int(get("rounds"))
                    deterministic = dict(master_key=None, password=password, rounds=rounds)
                    secret = dict(password=password)
                destination = io.BytesIO()
                v2._encrypt_stream(io.BytesIO(plain), destination, len(plain),
                                   metadata=metadata, chunk_log2=log2, key_id=key_id,
                                   salt=salt, nonce_prefix=prefix, **deterministic)
                self.assertEqual(destination.getvalue().hex(), get("container_hex"))
                self.assertEqual(destination.getvalue()[:64].hex(), get("header_hex"))
                reader = v2.Reader(BytesSource(bytes.fromhex(get("container_hex"))), **secret)
                self.assertEqual(reader.read(0, len(plain)), plain)
                self.assertEqual(reader.metadata(), metadata)
                self.assertEqual(reader.header.key_id, key_id)
                self.assertEqual(reader.header.kdf_id, int(get("kdf_id")))

    def test_random_and_cross_boundary_ranges(self):
        plain, cipher = self.make_container()
        reader = self.open(cipher)
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
        reader = v2.Reader(source, master_key=KEY)
        source.requests.clear()
        self.assertEqual(reader.read(4090, 20), plain[4090:4110])
        base = 64 + reader.header.metadata_size
        self.assertEqual(source.requests, [(base, 4112), (base + 4112, 4112)])
        source.requests.clear()
        self.assertEqual(reader.read(len(plain), 0), b"")
        self.assertEqual(source.requests, [])

    def test_metadata_is_opaque_bytes(self):
        _, cipher = self.make_container(metadata=bytes(range(256)))
        self.assertEqual(self.open(cipher).metadata(), bytes(range(256)))

    def test_empty_metadata_and_absence_are_distinct(self):
        for metadata, flags, encoded_length in ((None, 0, 0), (b"", 1, 16)):
            _, cipher = self.make_container(metadata=metadata, size=0)
            reader = self.open(cipher)
            self.assertEqual(reader.metadata(), metadata)
            self.assertEqual(reader.header.flags, flags)
            self.assertEqual(reader.header.metadata_size, encoded_length)
            self.assertEqual(reader.read(0, 0), b"")
            self.assertEqual(len(cipher), 64 + encoded_length)

    def test_wrong_secret_and_changed_header_fail_authentication(self):
        for password in (None, "test-password"):
            _, cipher = self.make_container(password=password)
            wrong = {"password": "wrong-password"} if password is not None \
                else {"master_key": bytes(32)}
            with self.subTest(mode=password), self.assertRaises(AuthenticationError):
                v2.Reader(BytesSource(cipher), **wrong)
            for offset in (14, 32, 48):
                changed = bytearray(cipher)
                changed[offset] ^= 1
                with self.subTest(mode=password, offset=offset), \
                        self.assertRaises(AuthenticationError):
                    self.open(changed, password)

    def test_changed_data_and_metadata_fail_before_returning_plaintext(self):
        _, cipher = self.make_container(metadata=b"metadata")
        for target in ("metadata", "data"):
            changed = bytearray(cipher)
            header = v2.parse_header(cipher[:64])
            changed[64 if target == "metadata" else header.chunk_offset(0)] ^= 1
            reader = self.open(changed)
            with self.subTest(target=target), self.assertRaises(AuthenticationError):
                reader.metadata() if target == "metadata" else reader.read_chunk(0)

    def test_unread_records_are_not_claimed_to_be_authenticated(self):
        plain, cipher = self.make_container()
        changed = bytearray(cipher)
        header = v2.parse_header(cipher[:64])
        changed[header.chunk_offset(2)] ^= 1
        reader = self.open(changed)
        self.assertEqual(reader.read(0, 20), plain[:20])
        with self.assertRaises(AuthenticationError):
            v2.decrypt_stream(reader, io.BytesIO())

    def test_swapping_records_fails_authentication(self):
        _, cipher = self.make_container(size=3 * 4096)
        changed = bytearray(cipher)
        first = cipher[64:64 + 4112]
        second = cipher[64 + 4112:64 + 8224]
        changed[64:64 + 4112] = second
        changed[64 + 4112:64 + 8224] = first
        reader = self.open(changed)
        with self.assertRaises(AuthenticationError):
            reader.read_chunk(0)

    def test_record_substitution_across_containers_fails(self):
        plain, first = self.make_container(size=2 * 4096)
        _, second = self.make_container(size=2 * 4096)
        changed = bytearray(first)
        changed[64:64 + 4112] = second[64:64 + 4112]
        with self.assertRaises(AuthenticationError):
            self.open(changed).read_chunk(0)

    def test_truncated_and_overlong_containers_are_rejected(self):
        _, cipher = self.make_container(metadata=b"x")
        for data in (cipher[:63], cipher[:64], cipher[:-1], cipher + b"x"):
            with self.subTest(size=len(data)), self.assertRaises(FormatError):
                self.open(data)

    def test_short_byte_range_response_is_rejected(self):
        _, cipher = self.make_container()

        class ShortRange(BytesSource):
            def read_at(self, offset, length):
                data = super().read_at(offset, length)
                return data if offset == 0 else data[:-1]

        reader = v2.Reader(ShortRange(cipher), master_key=KEY)
        with self.assertRaises(FormatError):
            reader.read_chunk(0)

    def test_malformed_fields_are_rejected(self):
        changes = (
            (0, b"XXXX"), (4, b"\x03"), (5, b"\x02"), (6, b"\x0b"),
            (6, b"\x1b"), (7, b"\x00"), (7, b"\x03"),
            (8, struct.pack("<I", 1)),
            (12, b"\x10\x00"),
            (40, struct.pack("<Q", (1 << 64) - 1)),
        )
        for offset, replacement in changes:
            header = bytearray(synthetic_header())
            header[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset, replacement=replacement), \
                    self.assertRaises(FormatError):
                v2.parse_header(bytes(header))
        password_changes = (
            (8, bytes(4)), (8, struct.pack("<I", 0x80000000)),
        )
        for offset, replacement in password_changes:
            header = bytearray(synthetic_header(kdf=1, rounds=1000))
            header[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset, replacement=replacement), \
                    self.assertRaises(FormatError):
                v2.parse_header(bytes(header))
        header = bytearray(synthetic_header())
        header[5] = 1
        with self.assertRaises(FormatError):
            v2.parse_header(bytes(header))

    def test_nonce_counter_and_64_bit_offset_boundaries(self):
        size = (1 << 33) + 12345
        header = v2.parse_header(synthetic_header(size=size, log2=20))
        self.assertEqual(header.chunk_count, 8193)
        self.assertGreater(header.chunk_offset(4096), (1 << 31) - 1)
        limit = MAX_CHUNKS * 4096
        header = v2.parse_header(synthetic_header(size=limit))
        self.assertEqual(header.chunk_count, MAX_CHUNKS)
        header.chunk_offset(MAX_CHUNKS - 1)
        with self.assertRaises(FormatError):
            header.chunk_offset(MAX_CHUNKS)
        with self.assertRaises(FormatError):
            v2.parse_header(synthetic_header(size=limit + 1))

    def test_range_bounds(self):
        plain, cipher = self.make_container()
        reader = self.open(cipher)
        for offset, length in ((-1, 1), (0, -1), (len(plain), 1), (1 << 63, 1)):
            with self.subTest(offset=offset, length=length), self.assertRaises(FormatError):
                reader.read(offset, length)

    def test_reader_kdf_policy_is_checked_before_derivation(self):
        header = bytearray(synthetic_header(kdf=1, rounds=6_000_000))
        with patch("chunkseal.v2._password_ikm", side_effect=AssertionError("KDF must not run")):
            with self.assertRaisesRegex(FormatError, "policy"):
                v2.Reader(BytesSource(header), password="password")
        cipher = v2.encrypt_bytes(b"x", password="password", rounds=3000)
        with self.assertRaises(FormatError):
            v2.Reader(BytesSource(cipher), password="password", max_rounds=2000)
        reader = v2.Reader(BytesSource(cipher), password="password", max_rounds=4000)
        self.assertEqual(reader.read(0, 1), b"x")

    def test_metadata_length_limit(self):
        cipher = v2.encrypt_bytes(b"", master_key=KEY, metadata=bytes(65519))
        self.assertEqual(len(v2.Reader(BytesSource(cipher), master_key=KEY).metadata()), 65519)
        with self.assertRaises(FormatError):
            v2.encrypt_bytes(b"", master_key=KEY, metadata=bytes(65520))

    def test_streaming_short_reads_and_short_writes(self):
        plain = bytes(range(256)) * 35

        class ShortReads(io.BytesIO):
            def read(self, length=-1):
                return super().read(min(length, 37) if length >= 0 else 37)

        class ShortWrites(io.BytesIO):
            def write(self, data):
                return super().write(data[:9])

        destination = ShortWrites()
        v2.encrypt_stream(ShortReads(plain), destination, len(plain),
                          master_key=KEY, chunk_log2=12)
        result = io.BytesIO()
        source = FileSource(io.BytesIO(destination.getvalue()))
        v2.decrypt_stream(v2.Reader(source, master_key=KEY), result)
        self.assertEqual(result.getvalue(), plain)

    def test_declared_input_size_must_match_stream(self):
        for declared_size in (0, 2):
            with self.assertRaises(FormatError):
                v2.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), declared_size, master_key=KEY)

    def test_passwords_are_strict_utf8_without_normalization(self):
        first = v2.encrypt_bytes(b"x", password="é", rounds=1000, chunk_log2=12)
        second = v2.encrypt_bytes(b"x", password="e\u0301", rounds=1000, chunk_log2=12)
        self.assertNotEqual(first[64:], second[64:])
        with self.assertRaises(FormatError):
            v2.encrypt_bytes(b"x", password="\ud800", rounds=1000)
        cipher = v2.encrypt_bytes(b"x", password="a\x00b", rounds=1000)
        self.assertEqual(v2.Reader(BytesSource(cipher), password="a\x00b").read(0, 1), b"x")

    def test_default_writer_uses_fresh_salt_and_nonce(self):
        for secret in ({"master_key": KEY}, {"password": "password"}):
            first = v2.encrypt_bytes(b"x", **secret)
            second = v2.encrypt_bytes(b"x", **secret)
            header = v2.parse_header(first[:64])
            self.assertEqual(header.chunk_log2, 20)
            self.assertEqual(header.rounds, 0 if "master_key" in secret else 600_000)
            self.assertNotEqual(first[16:32], second[16:32])
            self.assertNotEqual(first[32:40], second[32:40])
            self.assertEqual(v2.Reader(BytesSource(first), **secret).read(0, 1), b"x")

    def test_typed_secrets_are_enforced(self):
        with self.assertRaises(FormatError):
            v2.encrypt_bytes(b"x")
        with self.assertRaises(FormatError):
            v2.encrypt_bytes(b"x", master_key=KEY, password="password")
        with self.assertRaises(TypeError):
            v2.encrypt_bytes(b"x", master_key=KEY.hex())
        with self.assertRaises(TypeError):
            v2.encrypt_bytes(b"x", password=b"password")
        for length in (0, 15, 17, 31, 33, 64):
            with self.subTest(length=length), self.assertRaises(FormatError):
                v2.encrypt_bytes(b"x", master_key=bytes(length))
        with self.assertRaises(FormatError):
            v2.encrypt_bytes(b"x", master_key=KEY, rounds=1)
        with self.assertRaises(FormatError):
            v2.encrypt_bytes(b"x", password="password", rounds=0)
        for length in (16, 32):
            cipher = v2.encrypt_bytes(b"x", master_key=bytes(length))
            self.assertEqual(v2.Reader(BytesSource(cipher), master_key=bytes(length)).read(0, 1), b"x")

    def test_reader_rejects_mistyped_secret_before_kdf(self):
        raw = v2.encrypt_bytes(b"x", master_key=KEY)
        password = v2.encrypt_bytes(b"x", password="password", rounds=1000)
        with patch("chunkseal.v2._password_ikm", side_effect=AssertionError("KDF must not run")):
            with self.assertRaises(FormatError):
                v2.Reader(BytesSource(raw), password="password")
        with self.assertRaises(FormatError):
            v2.Reader(BytesSource(password), master_key=KEY)
        with self.assertRaises(TypeError):
            v2.Reader(BytesSource(raw), master_key=KEY.hex())
        with self.assertRaises(TypeError):
            v2.Reader(BytesSource(password), password=b"password")
        with self.assertRaises(FormatError):
            v2.Reader(BytesSource(raw))

    def test_versions_reject_each_other_and_dispatch_is_exact(self):
        plain, raw = self.make_container(size=100)
        _, password = self.make_container(size=100, password="test-password")
        v1 = encrypt_bytes(plain, "test-password", rounds=1000, chunk_log2=12)
        with self.assertRaises(FormatError):
            Reader(BytesSource(raw), "test-password")
        with self.assertRaises(FormatError):
            v2.Reader(BytesSource(v1), password="test-password")
        self.assertEqual(open_reader(BytesSource(raw), master_key=KEY).read(0, 100), plain)
        self.assertEqual(open_reader(BytesSource(password), password="test-password")
                         .read(0, 100), plain)
        self.assertEqual(open_reader(BytesSource(v1), password="test-password")
                         .read(0, 100), plain)
        with self.assertRaises(FormatError):
            open_reader(BytesSource(v1), master_key=KEY)
        with self.assertRaises(FormatError):
            open_reader(BytesSource(raw), password="test-password")
        for version in (0, 3, 255):
            changed = bytearray(raw)
            changed[4] = version
            with self.subTest(version=version), self.assertRaises(FormatError):
                open_reader(BytesSource(changed), master_key=KEY)
        changed = bytearray(raw)
        changed[:4] = b"NCMX"
        with self.assertRaises(FormatError):
            open_reader(BytesSource(changed), master_key=KEY)
        with self.assertRaises(FormatError):
            open_reader(BytesSource(raw[:4]), master_key=KEY)


if __name__ == "__main__":
    unittest.main()