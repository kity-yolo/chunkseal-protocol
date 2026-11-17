# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ChunkSeal contributors
# Additional GPLv3 permission for Tingyu: see ADDITIONAL-PERMISSION.md.
"""ChunkSeal v1: a seekable authenticated encrypted container."""

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

__all__ = [
    "AAD_SIZE", "DEFAULT_CHUNK_LOG2", "DEFAULT_MAX_ROUNDS", "DEFAULT_ROUNDS",
    "HEADER_SIZE", "MAGIC", "MAX_CHUNKS", "TAG_SIZE", "VERSION",
    "AuthenticationError", "BytesSource", "FileSource", "FormatError",
    "Header", "Reader", "decrypt_stream", "derive_key", "encrypt_bytes",
    "encrypt_stream", "parse_header",
]
