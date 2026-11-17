# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ChunkSeal contributors
"""Reference implementation of the byte format specified in SPEC.md."""

from __future__ import annotations

import hashlib
import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CSEA"
VERSION = 1
HEADER_SIZE = 64
AAD_SIZE = 48
TAG_SIZE = 16
DEFAULT_CHUNK_LOG2 = 20
DEFAULT_ROUNDS = 600_000
DEFAULT_MAX_ROUNDS = 2_000_000
MAX_CHUNKS = 0xFFFFFFFE
_HEADER_COUNTER = 0xFFFFFFFF
_METADATA_COUNTER = 0xFFFFFFFE
_PREFIX = struct.Struct("<4sBBBBIHH16s8sQ")


class FormatError(ValueError):
    """Unsupported, malformed, truncated, or out-of-bounds container."""


class AuthenticationError(FormatError):
    """A password or an authenticated record failed verification."""


class Source(Protocol):
    def size(self) -> int: ...
    def read_at(self, offset: int, length: int) -> bytes: ...


class BytesSource:
    def __init__(self, data: bytes):
        self._data = bytes(data)

    def size(self) -> int:
        return len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise FormatError("Negative source range")
        return self._data[offset:offset + length]


class FileSource:
    """A caller-owned seekable file. Access to one instance is serialized."""

    def __init__(self, file: BinaryIO):
        self._file = file
        position = file.tell()
        file.seek(0, io.SEEK_END)
        self._size = file.tell()
        file.seek(position)

    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise FormatError("Negative source range")
        self._file.seek(offset)
        return _read_exact(self._file, length)


@dataclass(frozen=True)
class Header:
    flags: int
    chunk_log2: int
    rounds: int
    metadata_size: int
    key_id: int
    salt: bytes
    nonce_prefix: bytes
    plaintext_size: int
    aad: bytes
    tag: bytes

    @property
    def chunk_size(self) -> int:
        return 1 << self.chunk_log2

    @property
    def chunk_count(self) -> int:
        return (self.plaintext_size + self.chunk_size - 1) // self.chunk_size

    @property
    def file_size(self) -> int:
        return HEADER_SIZE + self.metadata_size + self.plaintext_size + TAG_SIZE * self.chunk_count

    def chunk_offset(self, index: int) -> int:
        if not 0 <= index < self.chunk_count:
            raise FormatError("Data chunk index outside container")
        return HEADER_SIZE + self.metadata_size + index * (self.chunk_size + TAG_SIZE)


def _validate_fields(flags: int, chunk_log2: int, rounds: int,
                     metadata_size: int, key_id: int, plaintext_size: int) -> None:
    if not 12 <= chunk_log2 <= 26:
        raise FormatError("chunk_log2 must be in 12..26")
    if not 1 <= rounds <= 0x7FFFFFFF:
        raise FormatError("PBKDF2 rounds outside supported range")
    if not 0 <= key_id <= 0xFFFF:
        raise FormatError("key_id must be in 0..65535")
    if flags not in (0, 1):
        raise FormatError("Unsupported flag bits")
    if (flags == 0 and metadata_size != 0) or (
        flags == 1 and not TAG_SIZE <= metadata_size <= 0xFFFF
    ):
        raise FormatError("Inconsistent metadata flag or length")
    if not 0 <= plaintext_size <= MAX_CHUNKS * (1 << chunk_log2):
        raise FormatError("Plaintext size overlaps reserved nonce counters")


def parse_header(data: bytes) -> Header:
    """Parse untrusted fields; this does not authenticate them."""
    if len(data) != HEADER_SIZE:
        raise FormatError("A header must contain exactly 64 bytes")
    magic, version, flags, log2, kdf, rounds, meta_size, key_id, salt, prefix, size = (
        _PREFIX.unpack(data[:AAD_SIZE])
    )
    if magic != MAGIC:
        raise FormatError("Unsupported file magic")
    if version != VERSION:
        raise FormatError("Unsupported version")
    if kdf != 1:
        raise FormatError("Unsupported KDF")
    _validate_fields(flags, log2, rounds, meta_size, key_id, size)
    return Header(flags, log2, rounds, meta_size, key_id, salt, prefix, size,
                  bytes(data[:AAD_SIZE]), bytes(data[AAD_SIZE:]))


def derive_key(password: str, salt: bytes, rounds: int) -> bytes:
    if len(salt) != 16 or not 1 <= rounds <= 0x7FFFFFFF:
        raise FormatError("Invalid PBKDF2 salt or rounds")
    try:
        encoded = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError("Password must be well-formed Unicode") from error
    return hashlib.pbkdf2_hmac("sha256", encoded, salt, rounds, dklen=32)


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = stream.read(length - len(result))
        if not part:
            raise FormatError("Truncated input")
        if len(part) > length - len(result):
            raise FormatError("Source returned too many bytes")
        result.extend(part)
    return bytes(result)


def _write_all(stream: BinaryIO, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        count = stream.write(remaining)
        if count is None or not 0 < count <= len(remaining):
            raise OSError("Output did not accept bytes")
        remaining = remaining[count:]


def _read_source(source: Source, offset: int, length: int) -> bytes:
    data = source.read_at(offset, length)
    if len(data) != length:
        raise FormatError("Source range length does not match request")
    return data


def encrypt_stream(source: BinaryIO, destination: BinaryIO, plaintext_size: int,
                   password: str, *, metadata: bytes | None = None,
                   chunk_log2: int = DEFAULT_CHUNK_LOG2,
                   rounds: int = DEFAULT_ROUNDS, key_id: int = 0) -> None:
    """Write a fresh container. Discard destination on any failure."""
    _encrypt_stream(
        source, destination, plaintext_size, password, metadata=metadata,
        chunk_log2=chunk_log2, rounds=rounds, key_id=key_id,
        salt=os.urandom(16), nonce_prefix=os.urandom(8),
    )


def _encrypt_stream(source: BinaryIO, destination: BinaryIO, plaintext_size: int,
                    password: str, *, metadata: bytes | None, chunk_log2: int,
                    rounds: int, key_id: int, salt: bytes, nonce_prefix: bytes) -> None:
    """Deterministic entry point used only to reproduce test fixtures."""
    if metadata is not None and not isinstance(metadata, bytes):
        raise TypeError("Metadata must be bytes or None")
    metadata_size = 0 if metadata is None else len(metadata) + TAG_SIZE
    flags = int(metadata is not None)
    _validate_fields(flags, chunk_log2, rounds, metadata_size, key_id, plaintext_size)
    if len(salt) != 16 or len(nonce_prefix) != 8:
        raise FormatError("Invalid salt or nonce prefix length")
    aad = _PREFIX.pack(MAGIC, VERSION, flags, chunk_log2, 1, rounds,
                       metadata_size, key_id, salt, nonce_prefix, plaintext_size)
    aes = AESGCM(derive_key(password, salt, rounds))
    tag = aes.encrypt(_nonce(nonce_prefix, _HEADER_COUNTER), b"", aad)
    _write_all(destination, aad + tag)
    if metadata is not None:
        _write_all(destination, aes.encrypt(_nonce(nonce_prefix, _METADATA_COUNTER),
                                           metadata, None))
    remaining = plaintext_size
    index = 0
    while remaining:
        count = min(1 << chunk_log2, remaining)
        block = _read_exact(source, count)
        _write_all(destination, aes.encrypt(_nonce(nonce_prefix, index), block, aad))
        remaining -= count
        index += 1
    if source.read(1):
        raise FormatError("Source contains more data than plaintext_size")


def encrypt_bytes(plaintext: bytes, password: str, *, metadata: bytes | None = None,
                  chunk_log2: int = DEFAULT_CHUNK_LOG2,
                  rounds: int = DEFAULT_ROUNDS, key_id: int = 0) -> bytes:
    destination = io.BytesIO()
    encrypt_stream(io.BytesIO(plaintext), destination, len(plaintext), password,
                   metadata=metadata, chunk_log2=chunk_log2, rounds=rounds, key_id=key_id)
    return destination.getvalue()


class Reader:
    """Authenticates the header on opening and each requested record on reading."""

    def __init__(self, source: Source, password: str, *,
                 max_rounds: int = DEFAULT_MAX_ROUNDS):
        self._source = source
        self.header = parse_header(_read_source(source, 0, HEADER_SIZE))
        if source.size() != self.header.file_size:
            raise FormatError("Container is truncated or has trailing bytes")
        if max_rounds < 1 or self.header.rounds > max_rounds:
            raise FormatError("PBKDF2 rounds exceed reader policy")
        self._aes = AESGCM(derive_key(password, self.header.salt, self.header.rounds))
        try:
            self._aes.decrypt(_nonce(self.header.nonce_prefix, _HEADER_COUNTER),
                              self.header.tag, self.header.aad)
        except InvalidTag as error:
            raise AuthenticationError("Password or header authentication failed") from error

    def metadata(self) -> bytes | None:
        header = self.header
        if not header.flags:
            return None
        record = _read_source(self._source, HEADER_SIZE, header.metadata_size)
        try:
            return self._aes.decrypt(_nonce(header.nonce_prefix, _METADATA_COUNTER),
                                     record, None)
        except InvalidTag as error:
            raise AuthenticationError("Metadata authentication failed") from error

    def read_chunk(self, index: int) -> bytes:
        header = self.header
        offset = header.chunk_offset(index)
        length = min(header.chunk_size, header.plaintext_size - index * header.chunk_size)
        record = _read_source(self._source, offset, length + TAG_SIZE)
        try:
            return self._aes.decrypt(_nonce(header.nonce_prefix, index),
                                     record, header.aad)
        except InvalidTag as error:
            raise AuthenticationError("Data chunk authentication failed") from error

    def read(self, offset: int, length: int) -> bytes:
        header = self.header
        if offset < 0 or length < 0 or offset > header.plaintext_size - length:
            raise FormatError("Requested range outside plaintext")
        if length == 0:
            return b""
        first = offset // header.chunk_size
        last = (offset + length - 1) // header.chunk_size
        result = bytearray()
        for index in range(first, last + 1):
            block = self.read_chunk(index)
            base = index * header.chunk_size
            begin = max(0, offset - base)
            end = min(len(block), offset + length - base)
            result.extend(block[begin:end])
        return bytes(result)


def decrypt_stream(reader: Reader, destination: BinaryIO) -> None:
    """Verify metadata and write all verified data records; discard on failure."""
    reader.metadata()
    for index in range(reader.header.chunk_count):
        _write_all(destination, reader.read_chunk(index))
