# ChunkSeal

Source repository: [kity-yolo/chunkseal-protocol](https://github.com/kity-yolo/chunkseal-protocol).

A chunked encrypted file container with random access. The input can be any file; a reader
fetches only the ciphertext chunks covering the requested range, verifies each chunk, and
returns the plaintext. It works with local files and storage that supports HTTP Range.

The latest protocol document is the **v2 draft**. Its default profile uses a client-held
random master key and fast HKDF derivation, so opening every file does not require an expensive
password KDF. The project also preserves the v1 specification, reference implementations,
and interoperability vectors.

- Protocol name: **ChunkSeal**
- File identifier: `CSEA`, hexadecimal `43 53 45 41`
- Suggested extension: `.cseal`
- Encryption: AES-256-GCM with a full 128-bit authentication tag
- v2 default derivation: HKDF-SHA256 from a 16- or 32-byte random master key
- v2 optional password mode: PBKDF2-HMAC-SHA256 followed by HKDF-SHA256
- Default chunk size: 1 MiB; header size: 64 bytes; overhead: 16 bytes per data record

| Artifact | Version and status |
| --- | --- |
| [SPEC.md](SPEC.md) | v2 draft: raw-key default, per-record keys, metadata bound to the header |
| [test-vectors/v2.properties](test-vectors/v2.properties) | v2 draft known-answer vectors |
| [SPEC-V1.md](SPEC-V1.md) | Original v1 format rules |
| Python / Java package `0.1.0`, examples, and `tools/check.sh` | v1 and v2 draft implementations and interoperability checks |

## Specification and implementations

[SPEC.md](SPEC.md) specifies v2's byte layout, explicit secret types, HKDF context,
authentication inputs, and read/write rules. [SPEC-V1.md](SPEC-V1.md) specifies the original
v1 format rules. [MIGRATION.md](MIGRATION.md) documents exact version dispatch and migration
of legacy or v1 containers.

The Python implementation ([v1](src/chunkseal/core.py), [v2](src/chunkseal/v2.py)) and the
Java implementation ([v1](reference/java/src/chunkseal/ChunkSeal.java),
[v2](reference/java/src/chunkseal/ChunkSealV2.java)) can be used independently. Both versions
support streaming writes, offset-based reads, and independent per-chunk authentication.
Each version's reader rejects the other version rather than reinterpreting it; Python's
`chunkseal.open_reader` dispatches by exact magic and version byte. v2 APIs take typed
secrets: raw `master_key` bytes for the default mode, or a Unicode `password` for the
optional password mode. Metadata is an optional encrypted byte string whose content is
defined by the caller.

## Using the Python implementation

~~~sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
~~~

v1 password containers:

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

v2 draft containers with a random master key (the default profile):

~~~python
import os

from chunkseal import BytesSource, open_reader, v2

master_key = os.urandom(32)  # keep this secret outside the stored container
ciphertext = v2.encrypt_bytes(
    b"Hello, ChunkSeal",
    master_key=master_key,
    metadata=b'{"name":"hello.txt"}',
)
reader = v2.Reader(BytesSource(ciphertext), master_key=master_key)
assert reader.read(7, 9) == b"ChunkSeal"
# open_reader also accepts v1 containers when given a password.
assert open_reader(BytesSource(ciphertext), master_key=master_key).read(7, 9) == b"ChunkSeal"
~~~

v2 password mode is explicit: pass `password=` instead of `master_key=`. A hex or base64
key export must be decoded to raw bytes before use; text is never guessed to be a key.

See [examples/roundtrip.py](examples/roundtrip.py) for a streaming file example. Every write by
the reference implementation generates a fresh random salt and random nonce prefix. Opening a
container verifies the header; reading verifies the chunks involved. To verify the entire file,
you must read all data chunks and the metadata.

## Checks

Requires Python 3.10 or later and JDK 17 or later:

~~~sh
CHUNKSEAL_PYTHON=.venv/bin/python bash tools/check.sh
~~~

These checks cover v1 and v2: fixed test vectors, two-way Python/Java interoperability in
both versions and both v2 modes, random and cross-chunk reads, Unicode passwords, wrong and
mistyped secrets, malformed and over-cost headers, tampering, record substitution and
reordering, truncation, trailing bytes, and parameter and counter boundaries. Test vectors
use fixed salts and nonces and serve only to validate implementations; regular write APIs
use random values. See the [validation record](VALIDATION.md) for this environment and the
check results.

To check the v2 draft vectors separately:

~~~sh
CHUNKSEAL_PYTHON=.venv/bin/python bash tools/check-v2-vectors.sh
~~~

The [Python vector helper](tools/check-v2-vectors.py) uses the cryptography HKDF and AES-GCM
implementations; the [Java vector helper](reference/java/test/chunkseal/V2DraftVectors.java)
independently uses JCE HMAC and AES-GCM. They compare exact intermediate keys, AAD, and complete
ciphertexts, check record authentication and selected ranges, and verify that the existing v1
readers reject v2. These helpers are not general v2 container APIs.

## v2 profile and format status

v2 targets client-encrypted storage and fast random reads. A random master key belongs to the
client; file salts and record context derive independent AES keys. Metadata and data authenticate
the immutable header, record kind, and counter. Random-key mode has `rounds = 0`; human-chosen
passwords use the separately selected password mode. An application can unlock a protected
master-key export once and use random-key mode for its collection.

The encrypted body remains directly seekable, with the same size overhead as v1. Identifying
filenames, public plaintext hashes, and plaintext catalogs can still disclose content; object
names should use random identifiers or ciphertext hashes. Storage policy, deletion, complete
valid-file replacement, and compromised-client protection are outside this profile.

v2 is a specification draft with draft vectors. The standalone packages implement the v2
draft alongside v1 and pass the conformance checks listed in `SPEC.md`; Android integration
and rollout are tracked in the application's validation record. Neither draft has completed
an independent cryptographic audit. v1 keeps the original chunk layout and authentication
rules. See `SPEC.md` for v2 rules and `SPEC-V1.md` for v1.

## License

Code and documentation are **AGPL-3.0-only**; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
The [Tingyu integration permission](ADDITIONAL-PERMISSION.md) permits covered original
material to be integrated into [Tingyu](https://github.com/qiuyuxc/tingyu) and distributed
as part of that program under **GPL-3.0-only**. Retain the copyright notices, permission
notice and [GPLv3 text](licenses/GPL-3.0.txt) with those copies. Third-party material and
contributions whose copyright holders have not adopted the permission retain their own licenses.
