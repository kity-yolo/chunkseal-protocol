"""Create and verify independent Python/Java interoperability fixtures."""

import argparse
from pathlib import Path

from chunkseal import BytesSource, Reader, encrypt_bytes

PASSWORD = "interop🔒-password"
PLAINTEXT = bytes((index * 53 + 7) & 255 for index in range(8191 + 17))
METADATA = '{"name":"interop.bin"}'.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("write", "verify"))
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    if arguments.operation == "write":
        data = encrypt_bytes(PLAINTEXT, PASSWORD, metadata=METADATA,
                             chunk_log2=12, rounds=1000, key_id=42)
        (arguments.directory / "python.cseal").write_bytes(data)
        return
    data = (arguments.directory / "java.cseal").read_bytes()
    reader = Reader(BytesSource(data), PASSWORD)
    assert reader.read(0, len(PLAINTEXT)) == PLAINTEXT
    assert reader.read(4090, 4098) == PLAINTEXT[4090:8188]
    assert reader.metadata() == METADATA
    assert reader.header.key_id == 42
    print("Python verified the independently written Java container.")


if __name__ == "__main__":
    main()
