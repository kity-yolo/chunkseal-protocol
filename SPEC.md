# ChunkSeal v1 specification

Status: draft for implementation and interoperability review.

The words MUST, MUST NOT, SHOULD, and MAY express requirements for a
conforming implementation. ChunkSeal is a container for arbitrary bytes.
Its recommended extension is `.cseal`. Filename extensions have no effect
on parsing or authentication.

## 1. Container layout

The container consists of a 64-byte header, an optional encrypted metadata
record, and zero or more encrypted data records, in that order.

All multibyte integers in the header are unsigned little-endian integers.
Nonce counters are unsigned **big-endian** integers.

| Offset | Bytes | Field | Required value or meaning |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII `CSEA`, hex `43534541` |
| 4 | 1 | version | `1` |
| 5 | 1 | flags | bit 0: metadata present; bits 1–7: zero |
| 6 | 1 | chunk_log2 | `12..26`; chunk size = `2 ** chunk_log2` bytes |
| 7 | 1 | kdf_id | `1`: PBKDF2-HMAC-SHA256 |
| 8 | 4 | rounds | `1..2,147,483,647` |
| 12 | 2 | metadata_size | encrypted metadata length, including its 16-byte tag |
| 14 | 2 | key_id | application-defined routing hint; zero means unspecified |
| 16 | 16 | salt | PBKDF2 salt |
| 32 | 8 | nonce_prefix | per-container nonce prefix |
| 40 | 8 | plaintext_size | original data length |
| 48 | 16 | header_tag | authentication tag over the first 48 header bytes |

The header is visible without a password. Its fields MUST NOT be treated
as authenticated until `header_tag` has been successfully verified.
`key_id` is public, is not a key, and is not proof of authorization.

Unknown magic, version, KDF, flag bits, or invalid field combinations
MUST be rejected. Without metadata, flag bit 0 and `metadata_size` are both
zero. With metadata, flag bit 0 is one and `metadata_size` is `16..65535`.
An explicitly present empty metadata record therefore occupies 16 bytes.

Let `C = 2 ** chunk_log2`, `P = plaintext_size`,
`M = metadata_size`, and `N = ceil(P / C)`, with `N = 0` when `P = 0`.
Then:

~~~
data_record_offset(i) = 64 + M + i * (C + 16)
data_plaintext_length(i) = min(C, P - i * C)
container_size = 64 + M + P + 16 * N
~~~

The container MUST have exactly `container_size` bytes. Truncation and
trailing bytes are invalid. A remote reader SHOULD obtain and check the
total container size even when fetching only byte ranges.

## 2. Key derivation and password encoding

The input password is Unicode text encoded to UTF-8. Implementations
MUST NOT implicitly trim it or normalize its Unicode representation.
Ill-formed Unicode input MUST be rejected instead of silently replacing
characters. This encoding is significant for cross-language compatibility.

~~~
key = PBKDF2-HMAC-SHA256(
    password_utf8_bytes,
    salt,
    rounds,
    output_length = 32 bytes
)
~~~

Writers SHOULD use at least 600,000 rounds, the reference writer default.
The values of 1,000 used in test vectors are for tests only.
Readers SHOULD impose a configurable maximum round count before running
PBKDF2, because the header is untrusted at that point.
The reference readers default to a maximum of 2,000,000 rounds.

## 3. AES-GCM and nonce construction

Use AES-256-GCM, a 12-byte nonce, and a full 16-byte authentication tag.
An encrypted record stores `ciphertext || tag`.

~~~
nonce = nonce_prefix[8 bytes] || uint32_be(counter)

counter = 0xFFFFFFFF   for the header
counter = 0xFFFFFFFE   for metadata
counter = i            for data record i
~~~

Valid data indices are `0..0xFFFFFFFD`. Accordingly `N` MUST NOT exceed
`0xFFFFFFFE`. This format ceiling is not a recommendation to encrypt that
many records with one key; applications must choose AES-GCM usage limits
appropriate to their required security level.

No nonce may ever be reused with the same AES key. Each encryption SHOULD
generate a fresh, cryptographically random 16-byte salt and a fresh
8-byte nonce prefix. The reference writers always do so.

A profile that deliberately reuses a derived key across containers MUST
ensure uniqueness of all their nonce prefixes, including retries and
crash recovery, and enforce an appropriate aggregate per-key usage limit.
An 8-byte random prefix alone does not guarantee uniqueness: after `q`
containers sharing a key, its birthday-collision probability is
approximately `q * (q - 1) / 2 ** 65` while that probability is small.
Fresh independent salts avoid deliberately sharing an AES key across
containers. Salt or prefix reuse from test fixtures MUST NOT be copied
into ordinary writers.

## 4. Authentication inputs

Define `H` as the first 48 bytes of the final header, including magic,
flags, lengths, salt, and nonce prefix.

| Record | Plaintext | Associated data |
| --- | --- | --- |
| header | empty byte string | `H` |
| metadata | application-defined metadata bytes | empty byte string |
| data i | plaintext bytes of chunk i | `H` |

The `header_tag` is the 16-byte result of encrypting an empty plaintext
with the header nonce and associated data `H`.
Metadata uses its reserved nonce and empty associated data, retaining
the original container's rule. It is still independently authenticated
by AES-GCM; its security requires nonce uniqueness under its key.

A writer can calculate `metadata_size` before encryption as
`len(metadata) + 16`. There is no length/authentication dependency cycle.
Adding header-associated data to metadata would change the v1 rules and
requires a separately versioned format.

Each record MUST be authenticated before its plaintext is returned.
Wrong passwords, modified header tags, and modified record tags MUST
cause authentication failure. A reader MUST NOT return partially decrypted
bytes from a record whose authentication failed.

Opening a container authenticates its header, not unread records.
Random-access readers authenticate only the records they actually read.
Whole-container verification requires checking all data records and any
metadata. Whole-container decryptors SHOULD publish their output only
after successful completion, or discard partial output on failure.

## 5. Seeking

For a non-empty requested interval `[offset, offset + length)`:

~~~
first = offset // C
last = (offset + length - 1) // C
~~~

Read and authenticate records `first..last`, then take the requested slices.
Both values MUST be nonnegative and `offset + length` MUST be at most `P`.
Implementations using fixed-width integers MUST check this without integer
overflow. A zero-length read at any offset in `0..P` returns empty bytes
without fetching data records.

Readers MUST use exact-length byte-range reads. Short records MUST fail,
and readers MUST reject records whose data index overlaps a reserved nonce.

## 6. Metadata and transport

Metadata is an opaque byte string with a maximum plaintext length of
65,519 bytes. Applications MAY define a UTF-8 JSON convention, but the
container does not require JSON, filenames, music tags, or any media type.

The format works with local seekable files and remote byte-range sources.
Authentication is independent of HTTP, S3, directory indexing, and
application account management. Implementations must validate the actual
range lengths supplied by their byte source.

The container reveals its original size, chunk size, KDF parameters,
key identifier, and whether metadata is present. It does not provide
availability, compression, version rollback protection, or protection
against an attacker replacing the complete file with another valid file.

## 7. Test vectors and reference implementations

`test-vectors/v1.properties` contains fixed known-answer vectors.
Byte-valued fields use hexadecimal ASCII; `-` means absent metadata,
while an empty value means present but empty metadata.
`password_utf8_hex` encodes the exact password bytes.
Fixtures include the derived key, complete header, complete container,
original plaintext, and expected metadata.

The Python and Java references must both reproduce the fixed bytes and
read containers generated by the other implementation.
Random salt and prefix generation makes ordinary encryptions intentionally
nondeterministic.

Protocol code and documentation: AGPL-3.0-only; see `LICENSE` and `NOTICE`.
