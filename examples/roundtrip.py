"""Run with: python examples/roundtrip.py"""

import tempfile
from pathlib import Path

from chunkseal import FileSource, Reader, decrypt_stream, encrypt_stream

payload = bytes((index * 37 + 19) & 255 for index in range(10_000))
password = "example-only-passphrase"

with tempfile.TemporaryDirectory(prefix="chunkseal-example-") as directory:
    root = Path(directory)
    plain = root / "example.bin"
    encrypted = root / "example.cseal"
    restored = root / "restored.bin"
    plain.write_bytes(payload)
    with plain.open("rb") as source, encrypted.open("wb") as destination:
        encrypt_stream(source, destination, plain.stat().st_size, password,
                       metadata=b'{"name":"example.bin"}')
    with encrypted.open("rb") as source, restored.open("wb") as destination:
        reader = Reader(FileSource(source), password)
        assert reader.read(4090, 100) == payload[4090:4190]
        assert reader.metadata() == b'{"name":"example.bin"}'
        decrypt_stream(reader, destination)
    assert restored.read_bytes() == payload
    print("ChunkSeal streaming and range-read example passed.")
