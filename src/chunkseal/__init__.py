# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ChunkSeal contributors
# Additional GPLv3 permission: see ADDITIONAL-PERMISSION.md.
"""ChunkSeal: seekable authenticated encrypted containers (v1 and v2 draft)."""

from . import v2
from .core import (
    AAD_SIZE,
    DEFAULT_CHUNK_LOG2,
    DEFAULT_MAX_ROUNDS,
    DEFAULT_ROUNDS,
    HEADER_SIZE,
    MAGIC,
    MAX_CHUNKS,
    TAG_SIZE,
    VERSION,
    AuthenticationError,
    BytesSource,
    FileSource,
    FormatError,
    Header,
    Reader,
    decrypt_stream,
    derive_key,
    encrypt_bytes,
    encrypt_stream,
    parse_header,
)

__version__ = "0.1.0"


def open_reader(source, *, master_key: bytes | None = None,
                password: str | None = None,
                max_rounds: int = DEFAULT_MAX_ROUNDS):
    """Dispatch by exact magic and version byte; never fall back after failure."""
    prefix = source.read_at(0, 5)
    if len(prefix) != 5:
        raise FormatError("A header must contain exactly 64 bytes")
    if prefix[:4] != MAGIC:
        raise FormatError("Unsupported file magic")
    if prefix[4] == VERSION:
        if master_key is not None:
            raise FormatError("v1 containers require a password, not a raw master key")
        if not isinstance(password, str):
            raise TypeError("password must be Unicode text, not bytes")
        return Reader(source, password, max_rounds=max_rounds)
    if prefix[4] == v2.VERSION:
        return v2.Reader(source, master_key=master_key, password=password,
                         max_rounds=max_rounds)
    raise FormatError("Unsupported version")


__all__ = [
    "AAD_SIZE", "DEFAULT_CHUNK_LOG2", "DEFAULT_MAX_ROUNDS", "DEFAULT_ROUNDS",
    "HEADER_SIZE", "MAGIC", "MAX_CHUNKS", "TAG_SIZE", "VERSION",
    "AuthenticationError", "BytesSource", "FileSource", "FormatError",
    "Header", "Reader", "decrypt_stream", "derive_key", "encrypt_bytes",
    "encrypt_stream", "open_reader", "parse_header", "v2",
]
