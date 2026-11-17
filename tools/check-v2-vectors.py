#!/usr/bin/env python3
"""Generate/check v2 draft vectors; not a packaged v2 file reader/writer."""
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ChunkSeal contributors
# Additional GPLv3 permission: see ADDITIONAL-PERMISSION.md.

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors/v2.properties"
LABEL = b"ChunkSeal/v2/record-key\x00"
PREFIX = struct.Struct("<4sBBBBIHH16s8sQ")
HEADER_COUNTER = 0xFFFFFFFF
METADATA_COUNTER = 0xFFFFFFFE
CHECKS = 0


def check(condition: bool, message: str) -> None:
    global CHECKS
    if not condition:
        raise AssertionError(message)
    CHECKS += 1


def cases() -> dict[str, dict]:
    return {
        "raw_empty": {
            "kdf_id": 2, "master_key_hex": bytes(range(16)).hex(),
            "rounds": 0, "chunk_log2": 12, "key_id": 0,
            "salt_hex": bytes(range(0x10, 0x20)).hex(),
            "nonce_prefix_hex": bytes(range(0x80, 0x88)).hex(),
            "plaintext_hex": "", "metadata_hex": "-",
        },
        "raw_boundary": {
            "kdf_id": 2, "master_key_hex": bytes(range(0x20, 0x40)).hex(),
            "rounds": 0, "chunk_log2": 12, "key_id": 7,
            "salt_hex": bytes(range(0x40, 0x50)).hex(),
            "nonce_prefix_hex": bytes(range(0x90, 0x98)).hex(),
            "plaintext_hex": bytes((i * 37 + 19) & 255 for i in range(8199)).hex(),
            "metadata_hex": (b"\x00\xffbinary\n" + "données".encode("utf-8")).hex(),
        },
        "raw_empty_metadata": {
            "kdf_id": 2, "master_key_hex": bytes(range(0xA0, 0xB0)).hex(),
            "rounds": 0, "chunk_log2": 12, "key_id": 42,
            "salt_hex": bytes(range(0x50, 0x60)).hex(),
            "nonce_prefix_hex": bytes(range(0xA0, 0xA8)).hex(),
            "plaintext_hex": b"utf8".hex(), "metadata_hex": "",
        },
        "password_unicode": {
            "kdf_id": 1,
            "password_utf8_hex": "clé🔒\x00e\u0301".encode("utf-8").hex(),
            "rounds": 1000, "chunk_log2": 12, "key_id": 65535,
            "salt_hex": bytes(range(0x60, 0x70)).hex(),
            "nonce_prefix_hex": bytes(range(0xB0, 0xB8)).hex(),
            "plaintext_hex": b"password-mode".hex(),
            "metadata_hex": '{"name":"données.bin"}'.encode("utf-8").hex(),
        },
    }


def input_material(case: dict) -> bytes:
    if case["kdf_id"] == 2:
        check(case["rounds"] == 0, "raw mode rounds")
        key = bytes.fromhex(case["master_key_hex"])
        check(len(key) in (16, 32), "raw key length")
        return key
    check(case["kdf_id"] == 1 and case["rounds"] > 0, "password mode")
    password = bytes.fromhex(case["password_utf8_hex"])
    check(password.decode("utf-8", errors="strict").encode("utf-8") == password,
          "strict UTF-8 password round trip")
    return hashlib.pbkdf2_hmac("sha256", password, bytes.fromhex(case["salt_hex"]),
                               case["rounds"], dklen=32)


def parameters(header: bytes, ikm: bytes, kind: int, counter: int) -> tuple[bytes, bytes, bytes]:
    record_id = bytes([kind]) + struct.pack(">I", counter)
    info = LABEL + header + record_id
    salt = header[16:32]
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)
    prk = hmac.digest(salt, ikm, "sha256")
    check(key == hmac.digest(prk, info + b"\x01", "sha256"), "HKDF single-block equivalence")
    aad = header + record_id
    check(len(aad) == 53, "AAD length")
    nonce = header[32:40] + struct.pack(">I", counter)
    return key, nonce, aad


def build(case: dict) -> tuple[dict, bytes, list[tuple[int, int, int, bytes]]]:
    plain = bytes.fromhex(case["plaintext_hex"])
    meta = None if case["metadata_hex"] == "-" else bytes.fromhex(case["metadata_hex"])
    meta_size = 0 if meta is None else len(meta) + 16
    header = PREFIX.pack(b"CSEA", 2, int(meta is not None), case["chunk_log2"],
                         case["kdf_id"], case["rounds"], meta_size, case["key_id"],
                         bytes.fromhex(case["salt_hex"]), bytes.fromhex(case["nonce_prefix_hex"]),
                         len(plain))
    check(len(header) == 48, "header prefix length")
    ikm = input_material(case)
    result = {key: str(value) for key, value in case.items()}
    result["ikm_hex"] = ikm.hex()
    result["prk_hex"] = hmac.digest(header[16:32], ikm, "sha256").hex()
    key, nonce, aad = parameters(header, ikm, 0, HEADER_COUNTER)
    result["header_key_hex"], result["header_aad_hex"] = key.hex(), aad.hex()
    output = bytearray(header + AESGCM(key).encrypt(nonce, b"", aad))
    result["header_hex"] = output.hex()
    # (kind, counter, ciphertext offset, plaintext) for independently read records.
    records = [(0, HEADER_COUNTER, 48, b"")]
    result["metadata_key_hex"] = result["metadata_aad_hex"] = "-"
    if meta is not None:
        key, nonce, aad = parameters(header, ikm, 1, METADATA_COUNTER)
        result["metadata_key_hex"], result["metadata_aad_hex"] = key.hex(), aad.hex()
        records.append((1, METADATA_COUNTER, len(output), meta))
        output.extend(AESGCM(key).encrypt(nonce, meta, aad))
    chunk_size = 1 << case["chunk_log2"]
    count = (len(plain) + chunk_size - 1) // chunk_size
    result["data_record_count"] = str(count)
    for index in range(count):
        block = plain[index * chunk_size:(index + 1) * chunk_size]
        check(len(output) == 64 + meta_size + index * (chunk_size + 16), "record offset")
        key, nonce, aad = parameters(header, ikm, 2, index)
        result[f"data_{index}_key_hex"], result[f"data_{index}_aad_hex"] = key.hex(), aad.hex()
        records.append((2, index, len(output), block))
        output.extend(AESGCM(key).encrypt(nonce, block, aad))
    check(len(output) == 64 + meta_size + len(plain) + count * 16, "container size")
    result["container_hex"] = output.hex()
    return result, bytes(output), records


def must_fail_tag(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, label: str) -> None:
    try:
        AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        check(True, label)
        return
    raise AssertionError(label)


def verify_crypto(case: dict, ciphertext: bytes, records: list[tuple[int, int, int, bytes]]) -> None:
    header = ciphertext[:48]
    ikm = input_material(case)
    for kind, counter, offset, plain in records:
        key, nonce, aad = parameters(header, ikm, kind, counter)
        record = ciphertext[offset:offset + len(plain) + 16]
        check(AESGCM(key).decrypt(nonce, record, aad) == plain, "record round trip")
        damaged = bytes([record[0] ^ 1]) + record[1:]
        must_fail_tag(key, nonce, damaged, aad, "tampered record rejected")
        must_fail_tag(key, nonce, record, aad[:-1] + bytes([aad[-1] ^ 1]), "wrong AAD rejected")
        altered_header = header[:14] + bytes([header[14] ^ 1]) + header[15:]
        changed_key, changed_nonce, changed_aad = parameters(altered_header, ikm, kind, counter)
        must_fail_tag(changed_key, changed_nonce, record, changed_aad, "changed header context rejected")
    wrong_ikm = bytes([ikm[0] ^ 1]) + ikm[1:]
    key, nonce, aad = parameters(header, wrong_ikm, 0, HEADER_COUNTER)
    must_fail_tag(key, nonce, ciphertext[48:64], aad, "wrong secret rejected")
    data = [record for record in records if record[0] == 2]
    if len(data) >= 2:
        kind, counter, _, plain = data[1]
        key, nonce, aad = parameters(header, ikm, kind, counter)
        other = ciphertext[data[0][2]:data[0][2] + len(plain) + 16]
        must_fail_tag(key, nonce, other, aad, "reordered data rejected")
    plain = bytes.fromhex(case["plaintext_hex"])
    chunk_size = 1 << case["chunk_log2"]
    meta_size = int.from_bytes(header[12:14], "little")
    for start, length in [(0, len(plain)), (len(plain), 0), (0, 0), (4094, 12), (8190, 9)]:
        if start + length > len(plain):
            continue
        recovered = bytearray()
        if length:
            for index in range(start // chunk_size, (start + length - 1) // chunk_size + 1):
                size = min(chunk_size, len(plain) - index * chunk_size)
                offset = 64 + meta_size + index * (chunk_size + 16)
                key, nonce, aad = parameters(header, ikm, 2, index)
                block = AESGCM(key).decrypt(nonce, ciphertext[offset:offset + size + 16], aad)
                base = index * chunk_size
                recovered.extend(block[max(0, start - base):min(size, start + length - base)])
        check(bytes(recovered) == plain[start:start + length], "vector range round trip")
    sys.path.insert(0, str(ROOT / "src"))
    from chunkseal import BytesSource, FormatError, Reader
    try:
        Reader(BytesSource(ciphertext), "v2-must-not-be-read-as-v1")
    except FormatError:
        check(True, "current v1 reader rejects v2")
    else:
        raise AssertionError("current v1 reader accepted v2")


def read_properties(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if line and not line.startswith("#"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Explicitly regenerate draft fixture bytes")
    args = parser.parse_args()
    expected = {"vectors": ",".join(cases())}
    for name, case in cases().items():
        fields, ciphertext, records = build(case)
        expected.update({f"{name}.{key}": value for key, value in fields.items()})
        verify_crypto(case, ciphertext, records)
    if args.write:
        comments = (
            "# ChunkSeal v2 draft known-answer vectors; fixed secrets/randomness are for tests only.\n"
            "# SPDX-License-Identifier: AGPL-3.0-only\n"
            "# Copyright (C) 2026 ChunkSeal contributors\n"
            "# Additional GPLv3 permission: see ADDITIONAL-PERMISSION.md.\n"
            "# Byte fields are hex. metadata_hex=- is absent; empty is present.\n"
            "# Only the optional password vector runs PBKDF2; its 1000 rounds are for tests only.\n"
        )
        VECTORS.write_text(comments + "\n".join(f"{key}={value}" for key, value in expected.items()) + "\n")
    actual = read_properties(VECTORS)
    check(actual == expected, "frozen v2 vector fields and bytes")
    print(f"Python v2 draft vectors: {len(cases())} vectors, {CHECKS} checks passed")


if __name__ == "__main__":
    main()
