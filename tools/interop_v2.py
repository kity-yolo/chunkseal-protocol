"""Create and verify independent Python/Java v2 interoperability fixtures."""

import argparse
from pathlib import Path

from chunkseal import BytesSource, v2

MASTER_KEY = bytes(range(0x20, 0x40))
PASSWORD = "interop🔒-v2-password"
PLAINTEXT = bytes((index * 53 + 7) & 255 for index in range(8191 + 17))
METADATA = '{"name":"interop-v2.bin"}'.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("write", "verify"))
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    if arguments.operation == "write":
        raw = v2.encrypt_bytes(PLAINTEXT, master_key=MASTER_KEY, metadata=METADATA,
                               chunk_log2=12, key_id=42)
        (arguments.directory / "python-v2-raw.cseal").write_bytes(raw)
        password = v2.encrypt_bytes(PLAINTEXT, password=PASSWORD, metadata=METADATA,
                                    chunk_log2=12, rounds=1000, key_id=42)
        (arguments.directory / "python-v2-pass.cseal").write_bytes(password)
        return
    raw = (arguments.directory / "java-v2-raw.cseal").read_bytes()
    reader = v2.Reader(BytesSource(raw), master_key=MASTER_KEY)
    assert reader.read(0, len(PLAINTEXT)) == PLAINTEXT
    assert reader.read(4090, 4098) == PLAINTEXT[4090:8188]
    assert reader.metadata() == METADATA
    assert reader.header.key_id == 42 and reader.header.kdf_id == 2
    password = (arguments.directory / "java-v2-pass.cseal").read_bytes()
    reader = v2.Reader(BytesSource(password), password=PASSWORD)
    assert reader.read(0, len(PLAINTEXT)) == PLAINTEXT
    assert reader.read(4090, 4098) == PLAINTEXT[4090:8188]
    assert reader.metadata() == METADATA
    assert reader.header.key_id == 42 and reader.header.kdf_id == 1
    print("Python verified the independently written Java v2 containers.")


if __name__ == "__main__":
    main()