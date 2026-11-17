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
