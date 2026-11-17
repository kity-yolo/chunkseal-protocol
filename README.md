# ChunkSeal

Source repository: [kity-yolo/chunkseal-protocol](https://github.com/kity-yolo/chunkseal-protocol).

A chunked encrypted file container with random access. The input can be any file; a reader
fetches only the ciphertext chunks covering the requested range, verifies each chunk, and
returns the plaintext. It works with local files and storage that supports HTTP Range.

This is currently a **v1 draft**. The project publishes the protocol specification, an
independent reference implementations and interoperability test vectors for implementers and
reviewers.

- Protocol name: **ChunkSeal**
- File identifier: `CSEA`, hexadecimal `43 53 45 41`
- Suggested extension: `.cseal`
- Encryption: AES-256-GCM with a full 128-bit authentication tag
- Key derivation: PBKDF2-HMAC-SHA256
- Default chunk size: 1 MiB; default derivation rounds: 600,000

## Specification and implementations

[SPEC.md](SPEC.md) specifies the byte layout, password encoding, authentication inputs and
read/write rules. [MIGRATION.md](MIGRATION.md) documents how to migrate legacy containers.

The [Python implementation](src/chunkseal/core.py) and the
[Java implementation](reference/java/src/chunkseal/ChunkSeal.java) can be used independently.
Both support streaming writes, offset-based reads and independent per-chunk authentication.
Metadata is an optional encrypted byte string whose content is defined by the caller.

## Using the Python implementation

~~~sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
~~~

~~~python
from chunkseal import BytesSource, Reader, encrypt_bytes

ciphertext = encrypt_bytes(
    b"Hello, ChunkSeal",
    "your passphrase",
    metadata=b'{"name":"hello.txt"}',
)
reader = Reader(BytesSource(ciphertext), "your passphrase")
assert reader.read(7, 9) == b"ChunkSeal"
assert reader.metadata() == b'{"name":"hello.txt"}'
~~~

See [examples/roundtrip.py](examples/roundtrip.py) for a streaming file example. Every write by
the reference implementation generates a fresh random salt and random nonce prefix. Opening a
container verifies the header; reading verifies the chunks involved. To verify the entire file,
you must read all data chunks and the metadata.

## Checks

Requires Python 3.10 or later and JDK 17 or later:

~~~sh
CHUNKSEAL_PYTHON=.venv/bin/python bash tools/check.sh
~~~

The checks cover fixed test vectors, two-way Python/Java interoperability, random and
cross-chunk reads, Unicode passwords, wrong passwords, tampering, truncation, and parameter and
counter boundaries. Test vectors use fixed salts and nonces and serve only to validate
implementations; regular write APIs use random values. See the
[validation record](VALIDATION.md) for this environment and the check results.

## Format status

v1 keeps the chunk layout of the original container and uses a new file identifier. It is an
documented file format draft that has not yet undergone an independent cryptographic audit. See
`SPEC.md` for the complete encoding rules and the nonce usage conditions.

## License

Code and documentation are **AGPL-3.0-only**; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
The [Tingyu integration permission](ADDITIONAL-PERMISSION.md) permits covered original
material to be integrated into [Tingyu](https://github.com/qiuyuxc/tingyu) and distributed
as part of that program under **GPL-3.0-only**. Retain the copyright notices, permission
notice and [GPLv3 text](licenses/GPL-3.0.txt) with those copies. Third-party material and
contributions whose copyright holders have not adopted the permission retain their own licenses.
