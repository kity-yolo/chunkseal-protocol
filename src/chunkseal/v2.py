# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ChunkSeal contributors
# Additional GPLv3 permission: see ADDITIONAL-PERMISSION.md.
"""Reference implementation of the v2 draft byte format specified in SPEC.md."""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import (
    AAD_SIZE,
    DEFAULT_CHUNK_LOG2,
    DEFAULT_MAX_ROUNDS,
    DEFAULT_ROUNDS,
    HEADER_SIZE,
    MAGIC,
    MAX_CHUNKS,
    TAG_SIZE,
    AuthenticationError,
    BytesSource,
    FileSource,
    FormatError,
    Source,
    _nonce,
    _PREFIX,
    _read_exact,
    _read_source,
    _write_all,
)

VERSION = 2
LABEL = b"ChunkSeal/v2/record-key\x00"
HEADER_KIND = 0
METADATA_KIND = 1
DATA_KIND = 2
_HEADER_COUNTER = 0xFFFFFFFF
_METADATA_COUNTER = 0xFFFFFFFE


@dataclass(frozen=True)
class Header:
    flags: int
    chunk_log2: int
    kdf_id: int
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


def _validate_fields(flags: int, chunk_log2: int, kdf_id: int, rounds: int,
                     metadata_size: int, key_id: int, plaintext_size: int) -> None:
    if not 12 <= chunk_log2 <= 26:
        raise FormatError("chunk_log2 must be in 12..26")
    if kdf_id == 2:
        if rounds != 0:
            raise FormatError("Random-key mode requires zero rounds")
    elif kdf_id == 1:
        if not 1 <= rounds <= 0x7FFFFFFF:
            raise FormatError("PBKDF2 rounds outside supported range")
    else:
        raise FormatError("Unsupported KDF")
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
    _validate_fields(flags, log2, kdf, rounds, meta_size, key_id, size)
    return Header(flags, log2, kdf, rounds, meta_size, key_id, salt, prefix, size,
                  bytes(data[:AAD_SIZE]), bytes(data[AAD_SIZE:]))


def _check_secret_types(master_key: bytes | None, password: str | None) -> None:
    if (master_key is None) == (password is None):
        raise FormatError("Provide exactly one of master_key or password")
    if master_key is not None and not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be raw bytes, not text")
    if password is not None and not isinstance(password, str):
        raise TypeError("password must be Unicode text, not bytes")


def _master_key_bytes(master_key: bytes | bytearray) -> bytes:
    key = bytes(master_key)
    if len(key) not in (16, 32):
        raise FormatError("A master key must contain exactly 16 or 32 bytes")
    return key


def _password_ikm(password: str, salt: bytes, rounds: int) -> bytes:
    try:
        encoded = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError("Password must be well-formed Unicode") from error
    return hashlib.pbkdf2_hmac("sha256", encoded, salt, rounds, dklen=32)


def _record_id(kind: int, counter: int) -> bytes:
    return bytes([kind]) + struct.pack(">I", counter)


def _record_key(prk: bytes, header_aad: bytes, kind: int, counter: int) -> bytes:
    info = LABEL + header_aad + _record_id(kind, counter) + b"\x01"
    return hmac.digest(prk, info, "sha256")


def encrypt_stream(source: BinaryIO, destination: BinaryIO, plaintext_size: int, *,
                   master_key: bytes | None = None, password: str | None = None,
                   metadata: bytes | None = None,
                   chunk_log2: int = DEFAULT_CHUNK_LOG2,
                   rounds: int | None = None, key_id: int = 0) -> None:
    """Write a fresh v2 container. Discard destination on any failure."""
    _check_secret_types(master_key, password)
    if master_key is not None:
        if rounds not in (None, 0):
            raise FormatError("Random-key mode requires zero rounds")
        _encrypt_stream(
            source, destination, plaintext_size, master_key=_master_key_bytes(master_key),
            password=None, metadata=metadata, chunk_log2=chunk_log2, rounds=0,
            key_id=key_id, salt=os.urandom(16), nonce_prefix=os.urandom(8),
        )
    else:
        _encrypt_stream(
            source, destination, plaintext_size, master_key=None, password=password,
            metadata=metadata, chunk_log2=chunk_log2,
            rounds=DEFAULT_ROUNDS if rounds is None else rounds,
            key_id=key_id, salt=os.urandom(16), nonce_prefix=os.urandom(8),
        )


def _encrypt_stream(source: BinaryIO, destination: BinaryIO, plaintext_size: int, *,
                    master_key: bytes | None, password: str | None,
                    metadata: bytes | None, chunk_log2: int, rounds: int,
                    key_id: int, salt: bytes, nonce_prefix: bytes) -> None:
    """Deterministic entry point used only to reproduce test fixtures."""
    if metadata is not None and not isinstance(metadata, bytes):
        raise TypeError("Metadata must be bytes or None")
    metadata_size = 0 if metadata is None else len(metadata) + TAG_SIZE
    flags = int(metadata is not None)
    kdf_id = 2 if master_key is not None else 1
    _validate_fields(flags, chunk_log2, kdf_id, rounds, metadata_size, key_id, plaintext_size)
    if len(salt) != 16 or len(nonce_prefix) != 8:
        raise FormatError("Invalid salt or nonce prefix length")
    header_aad = _PREFIX.pack(MAGIC, VERSION, flags, chunk_log2, kdf_id, rounds,
                              metadata_size, key_id, salt, nonce_prefix, plaintext_size)
    if master_key is not None:
        ikm = _master_key_bytes(master_key)
    else:
        ikm = _password_ikm(password, salt, rounds)
    prk = hmac.digest(salt, ikm, "sha256")
    header_key = _record_key(prk, header_aad, HEADER_KIND, _HEADER_COUNTER)
    tag = AESGCM(header_key).encrypt(_nonce(nonce_prefix, _HEADER_COUNTER), b"",
                                     header_aad + _record_id(HEADER_KIND, _HEADER_COUNTER))
    _write_all(destination, header_aad + tag)
    if metadata is not None:
        key = _record_key(prk, header_aad, METADATA_KIND, _METADATA_COUNTER)
        aad = header_aad + _record_id(METADATA_KIND, _METADATA_COUNTER)
        _write_all(destination, AESGCM(key).encrypt(
            _nonce(nonce_prefix, _METADATA_COUNTER), metadata, aad))
    remaining = plaintext_size
    index = 0
    while remaining:
        count = min(1 << chunk_log2, remaining)
        block = _read_exact(source, count)
        key = _record_key(prk, header_aad, DATA_KIND, index)
        aad = header_aad + _record_id(DATA_KIND, index)
        _write_all(destination, AESGCM(key).encrypt(_nonce(nonce_prefix, index), block, aad))
        remaining -= count
        index += 1
    if source.read(1):
        raise FormatError("Source contains more data than plaintext_size")


def encrypt_bytes(plaintext: bytes, *, master_key: bytes | None = None,
                  password: str | None = None, metadata: bytes | None = None,
                  chunk_log2: int = DEFAULT_CHUNK_LOG2,
                  rounds: int | None = None, key_id: int = 0) -> bytes:
    destination = io.BytesIO()
    encrypt_stream(io.BytesIO(plaintext), destination, len(plaintext),
                   master_key=master_key, password=password, metadata=metadata,
                   chunk_log2=chunk_log2, rounds=rounds, key_id=key_id)
    return destination.getvalue()


class Reader:
    """Authenticates the header on opening and each requested record on reading."""

    def __init__(self, source: Source, *, master_key: bytes | None = None,
                 password: str | None = None,
                 max_rounds: int = DEFAULT_MAX_ROUNDS):
        _check_secret_types(master_key, password)
        self._source = source
        self.header = parse_header(_read_source(source, 0, HEADER_SIZE))
        if source.size() != self.header.file_size:
            raise FormatError("Container is truncated or has trailing bytes")
        if self.header.kdf_id == 2:
            if master_key is None:
                raise FormatError("Container requires a raw master key, not a password")
            ikm = _master_key_bytes(master_key)
        else:
            if password is None:
                raise FormatError("Container requires a password, not a raw master key")
            if max_rounds < 1 or self.header.rounds > max_rounds:
                raise FormatError("PBKDF2 rounds exceed reader policy")
            ikm = _password_ikm(password, self.header.salt, self.header.rounds)
        self._prk = hmac.digest(self.header.salt, ikm, "sha256")
        key = _record_key(self._prk, self.header.aad, HEADER_KIND, _HEADER_COUNTER)
        aad = self.header.aad + _record_id(HEADER_KIND, _HEADER_COUNTER)
        try:
            AESGCM(key).decrypt(_nonce(self.header.nonce_prefix, _HEADER_COUNTER),
                                self.header.tag, aad)
        except InvalidTag as error:
            raise AuthenticationError("Secret or header authentication failed") from error

    def metadata(self) -> bytes | None:
        header = self.header
        if not header.flags:
            return None
        record = _read_source(self._source, HEADER_SIZE, header.metadata_size)
        key = _record_key(self._prk, header.aad, METADATA_KIND, _METADATA_COUNTER)
        aad = header.aad + _record_id(METADATA_KIND, _METADATA_COUNTER)
        try:
            return AESGCM(key).decrypt(_nonce(header.nonce_prefix, _METADATA_COUNTER),
                                       record, aad)
        except InvalidTag as error:
            raise AuthenticationError("Metadata authentication failed") from error

    def read_chunk(self, index: int) -> bytes:
        header = self.header
        offset = header.chunk_offset(index)
        length = min(header.chunk_size, header.plaintext_size - index * header.chunk_size)
        record = _read_source(self._source, offset, length + TAG_SIZE)
        key = _record_key(self._prk, header.aad, DATA_KIND, index)
        aad = header.aad + _record_id(DATA_KIND, index)
        try:
            return AESGCM(key).decrypt(_nonce(header.nonce_prefix, index), record, aad)
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