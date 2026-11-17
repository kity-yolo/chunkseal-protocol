# Validation record

Date: 2026-11-14.

This record covers the standalone ChunkSeal v1 draft and the 0.1.0 reference implementation.

| Environment | Version |
| --- | --- |
| Python | 3.12.3 |
| cryptography | 50.0.2 |
| JDK | OpenJDK 21.0.12 |
| Java compile target | JDK 17, UTF-8 source encoding |

How to run:

~~~sh
CHUNKSEAL_PYTHON=python3 bash tools/check.sh
~~~

- Python: 20 checks passed.
- Java: 199 assertions passed; compiled with `-Xlint:all -Werror`.
- Three fixed known-answer vectors were reproduced separately by Python and Java, with derived
  keys, headers and ciphertexts byte-for-byte identical.
- Python-written/Java-read and Java-written/Python-read both passed.
- The checks covered random and cross-chunk reads, Unicode passwords, empty and binary metadata,
  wrong passwords, header and record tampering, chunk reordering, truncation, extra bytes, KDF
  resource limits and 64-bit offsets.

This record describes implementation test results. The protocol remains a v1 draft, and
independent cryptographic audit has not yet been completed.

## v2 draft and vector review — 2026-11-17

This review updates the protocol draft in `SPEC.md`, preserves the original format rules
in `SPEC-V1.md`, and adds separate v2 draft vectors. The packaged Python / Java APIs still
implement v1. Application integration and rollout are tracked separately; no file migration
was performed in this protocol review, and these results do not claim a conforming general
v2 reader or writer.

| Environment | Version |
| --- | --- |
| Python (`python` in this environment) | 3.14.6 |
| cryptography | 50.0.1 |
| OpenJDK | 21.0.12 |
| Java compile target | JDK 17, UTF-8, `-Xlint:all -Werror` |

Commands used in this environment, whose `python3` lacks the cryptography dependency:

~~~sh
CHUNKSEAL_PYTHON=python bash tools/check-v2-vectors.sh
CHUNKSEAL_PYTHON=python bash tools/check.sh
~~~

- Four v2 known-answer vectors matched independently in Python and Java, including IKM, PRK,
  per-record keys, 53-byte AAD, complete headers, and complete ciphertexts.
- Python's cryptography HKDF calculation also matched the explicit HMAC-SHA256 single-block
  expansion formula. Python passed 201 checks; Java passed 146 assertions.
- Vectors cover 16- and 32-byte random master keys, an empty file, absent and explicitly empty
  metadata, binary metadata, two full data chunks and a partial tail, and a Unicode password
  containing an embedded NUL and decomposed character.
- Record round trips, wrong secrets, changed header context, tampered ciphertext and AAD,
  chunk reordering, selected cross-chunk ranges, and zero-length/EOF ranges passed.
- Existing Python and Java v1 readers rejected the v2 vectors; the v1 suite passed its original
  20 Python tests, 199 Java assertions, and two-way Python / Java interoperability checks.
- Before the license-notice update, the archived v1 specification had SHA-256
  `8fb8173f58e132d9480b13e7ab61f068f960ff0b31a7e2ca0b3d5fd214abdb7a`.
  At that review, existing v1 implementations, vectors, package metadata, and the original
  check script matched their pre-edit hashes. The permission update changes the specification's
  licensing footer and attribution comments in source and vectors; format rules and vector
  fields remain unchanged. Local documentation links and code fences were checked.

The vector helpers exercise fixed draft cases, not a general parser for untrusted v2 inputs.
Malformed-header/resource-limit handling, full stream APIs, complete boundary coverage, and
runtime/application integration remain part of the conformance work listed in `SPEC.md`.
An independent cryptographic audit has not been completed.

## v2 reference implementation — 2026-11-17

The packaged Python and Java APIs now implement the v2 draft alongside v1:
`chunkseal.v2` / `chunkseal.ChunkSealV2` with typed secrets (raw master key bytes or
Unicode password), HKDF per-record keys, 53-byte header-bound AAD, streaming writes,
offset reads, and whole-container verification. Python adds `chunkseal.open_reader`
for exact magic/version dispatch. The v1 APIs, vectors, and behavior are unchanged.
The protocol remains a v2 draft; this is implementation test results, not an audit.

| Environment | Version |
| --- | --- |
| Python (`python` in this environment) | 3.14.6 |
| cryptography | 50.0.1 |
| OpenJDK | 21.0.12 |
| Java compile target | JDK 17, UTF-8, `-Xlint:all -Werror` |

Commands used in this environment, whose `python3` lacks the cryptography dependency:

~~~sh
CHUNKSEAL_PYTHON=python bash tools/check.sh
CHUNKSEAL_PYTHON=python bash tools/check-v2-vectors.sh
~~~

- Python: 44 tests passed (20 v1 + 24 v2).
- Java: v1 suite passed its original 199 assertions; the v2 suite passed 244 assertions.
- The packaged Python and Java v2 writers each independently reproduced all four frozen
  v2 vectors byte-for-byte (complete containers and headers), and the packaged readers
  recovered the expected plaintext and metadata from the frozen containers.
- Two-way interoperability passed for v1 and for both v2 modes (32-byte raw key and
  Unicode password): Python-written/Java-read and Java-written/Python-read, including
  cross-chunk ranges, metadata, and key identifiers.
- v2 checks covered typed-secret enforcement and mistyped-secret rejection before any
  password KDF, 16- and 32-byte master keys, wrong secrets, malformed headers (magic,
  version, flag bits, KDF/rounds combinations, chunk range, metadata consistency, size
  ceiling), reader rounds policy, header-context and record tampering, record reordering
  and cross-container substitution, truncation and trailing bytes, short byte-range
  responses, Unicode passwords (embedded NUL, decomposed characters, surrogate
  rejection), metadata length limits and empty/absent distinction, streaming short
  reads/writes, declared-size mismatch, fresh salt and nonce prefix per write, 64-bit
  offsets, counter boundaries, and zero-length/EOF reads.
- Each version's readers reject the other version's containers; `open_reader` dispatches
  v1 and both v2 modes exactly and rejects unknown magic or versions.
- The separate draft-vector helpers still passed: Python 201 checks, Java 146 assertions.

Application v2 integration, on-device playback, and rollout are not covered by
this record and remain tracked separately. No existing file was migrated. An independent
cryptographic audit has not been completed.

## License and distribution checks — 2026-11-17

- The source license is `AGPL-3.0-only`. The unmodified AGPLv3 text has SHA-256
  `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`.
- The GPLv3 integration permission identifies the ChunkSeal source repository and
  the Tingyu codebase at `https://github.com/qiuyuxc/tingyu`.
- The Python wheel and source distribution both include `LICENSE`, `NOTICE`,
  `ADDITIONAL-PERMISSION.md` and `licenses/GPL-3.0.txt`, byte-for-byte matching
  the repository files. Package metadata declares `AGPL-3.0-only` and includes
  the ChunkSeal repository URL.
