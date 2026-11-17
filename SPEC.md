# ChunkSeal v2 specification

Status: draft for design and interoperability review, 2026-11-17.

This is the v2 draft. The packaged Python and Java implementations provide v2 draft
APIs alongside the original v1 APIs, whose complete specification is preserved in
[SPEC-V1.md](SPEC-V1.md). The draft test vectors are separate from the v1
vectors. Updating this document does not enable v2 in an existing reader.

The words MUST, MUST NOT, SHOULD, and MAY express requirements for a
conforming implementation. ChunkSeal is a container for arbitrary bytes.
Its recommended extension is `.cseal`. Filename extensions have no effect
on parsing or authentication.

## 1. Goal and default profile

The primary use case is storing client-encrypted files on a storage
provider that must not receive their plaintext, while retaining efficient
local and HTTP Range reads. The client keeps the secret independently
from the stored ciphertext. This profile does not assume that the storage
provider is trusted with decryption credentials.

The default profile uses a cryptographically random master key and fast
HKDF-SHA256 derivation. Password-based derivation is an explicit optional
mode for human-chosen passwords. Increasing password-guessing cost is not
part of the default random-key path.

AES-256-GCM and full 16-byte tags are retained. v2 keeps the 64-byte header
and fixed-size data layout; it adds no key slots, attachments, variable
chunk index, compression, or mutable records. It does not promise that a
provider will retain an object or refrain from applying its policies.

## 2. Container layout

The container consists of a 64-byte header, an optional encrypted metadata
record, and zero or more encrypted data records, in that order.

All multibyte integers in the header are unsigned little-endian integers.
Nonce counters are unsigned **big-endian** integers.

| Offset | Bytes | Field | Required value or meaning |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII `CSEA`, hex `43534541` |
| 4 | 1 | version | `2` |
| 5 | 1 | flags | bit 0: metadata present; bits 1–7: zero |
| 6 | 1 | chunk_log2 | `12..26`; chunk size = `2 ** chunk_log2` bytes |
| 7 | 1 | kdf_id | `2`: random-key HKDF-SHA256, the default; `1`: password PBKDF2 followed by HKDF-SHA256 |
| 8 | 4 | rounds | `0` in mode `2`; `1..2,147,483,647` in mode `1` |
| 12 | 2 | metadata_size | encrypted metadata length, including its 16-byte tag |
| 14 | 2 | key_id | application-defined routing hint; zero means unspecified |
| 16 | 16 | salt | fresh per-container derivation salt |
| 32 | 8 | nonce_prefix | per-container nonce prefix |
| 40 | 8 | plaintext_size | original data length |
| 48 | 16 | header_tag | empty-plaintext header record tag, as defined in section 5 |

The header is visible without a secret. Its fields MUST NOT be treated
as authenticated until `header_tag` has been successfully verified.
`key_id` is public, is not a key, and is not proof of authorization.

Unknown magic, version, KDF, flag bits, or invalid field combinations
MUST be rejected. In particular, mode `2` with nonzero `rounds` and mode
`1` with zero `rounds` are invalid. Without metadata, flag bit 0 and `metadata_size` are both
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

`N` MUST NOT exceed `0xFFFFFFFE`; data record indices must not overlap the
reserved header and metadata counters. All size and offset arithmetic
MUST be checked for overflow before allocation or fetching. The format
ceiling is at most `0xFFFFFFFE * C` plaintext bytes.

The container MUST have exactly `container_size` bytes. Truncation and
trailing bytes are invalid. A complete local or remote reader MUST obtain
and check the actual total size. A metadata-prefix inspector MAY defer
this check, but MUST NOT claim complete-container validation until the
total size is available and has been checked.

## 3. Secret inputs and key derivation

### 3.1. Default random-key mode (`kdf_id = 2`)

The input is a master key of exactly 16 or 32 raw bytes. Writers SHOULD
generate new master keys as 32 cryptographically random bytes. The
16-byte option accommodates existing 128-bit random secrets. A master
key MAY protect multiple containers; each encryption still requires fresh
per-container randomness as specified in section 4.

The random-key API MUST accept a byte-oriented secret distinct from a
password API. Callers MUST NOT substitute a human-chosen password, a
public identifier, or a fixed application-wide constant for a random
master key. Key length alone does not establish randomness.

Hexadecimal and base64 are export encodings, not KDF input encodings. A
32-character hexadecimal export of a 16-byte random key MUST be explicitly
decoded to its 16 raw bytes by the caller before using mode `2`. Readers
MUST NOT guess whether a text string is a password or a key export.

For this mode:

~~~
rounds = 0
IKM = master_key_bytes
~~~

No PBKDF2, Argon2, or other deliberately expensive password KDF runs on
this path. HKDF produces pseudorandom keys from the existing secret; it
does not add entropy or password-guessing resistance.

### 3.2. Optional password mode (`kdf_id = 1`)

The password is Unicode text encoded to UTF-8. Implementations MUST NOT
implicitly trim it or normalize its Unicode representation. Ill-formed
Unicode input MUST be rejected instead of silently replacing characters.

~~~
IKM = PBKDF2-HMAC-SHA256(
    password_utf8_bytes,
    salt,
    rounds,
    output_length = 32 bytes
)
~~~

Password-mode writers SHOULD use at least 600,000 rounds. The 1,000 rounds
in draft test vectors are for tests only. Readers MUST apply a configured
maximum round count before running PBKDF2, because the header is not yet
authenticated. The recommended default maximum is 2,000,000 rounds.

This mode is explicitly selected by the writer. It is not a fallback for
a missing or invalid random key. Direct password-mode containers still
incur one password derivation per fresh salt.

An application that needs a password and fast opening of many files MAY
encrypt its random master key once in a separate password-protected key
export, then use random-key mode for the files. For example, the key
export can itself be a password-mode container with a 16- or 32-byte
payload. The application authenticates and unlocks that export once,
then supplies the recovered raw key to file readers. Key export storage,
backup, and lifecycle belong to the application, not the file header.

### 3.3. Record key derivation

Define `H` as the exact first 48 bytes of the final header, excluding
`header_tag`. It MUST be the original byte sequence, not reconstructed
from decoded fields. Every multibyte header field retains its on-disk
little-endian encoding inside `H`.

Using HKDF-SHA256 from [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html):

~~~
PRK = HKDF-Extract(salt, IKM)
LABEL = ASCII("ChunkSeal/v2/record-key") || 0x00
R = uint8(kind) || uint32_be(counter)
record_key = HKDF-Expand(PRK, LABEL || H || R, 32)
~~~

The zero byte at the end of `LABEL` is mandatory. Concatenation is over
raw bytes; no hex text, whitespace, or other separators are inserted.
The record kinds and counters are defined in section 4.

For SHA-256 and a 32-byte output, these operations are equivalently:

~~~
PRK = HMAC-SHA256(key = salt, message = IKM)
record_key = HMAC-SHA256(key = PRK, message = LABEL || H || R || 0x01)
~~~

Thus, the header, metadata, and each individual data chunk use different
derived AES keys. The per-container `PRK` can be cached for the lifetime
of the reader. A random read derives only the keys for its accessed
records and does not require an index or prior chunks.

v2 password mode also uses this HKDF step. Its PBKDF2 output MUST NOT be
used directly as an AES key, which would implement the v1 rule instead.

## 4. Records, nonces, and fresh writes

Use AES-256-GCM, a 12-byte nonce, and a full 16-byte authentication tag,
as specified by [RFC 5116 section 5.2](https://www.rfc-editor.org/rfc/rfc5116.html#section-5.2).
An encrypted record stores `ciphertext || tag`.

| Record | `kind` | `counter` | Plaintext |
| --- | --- | --- | --- |
| header | `0x00` | `0xFFFFFFFF` | empty byte string |
| metadata | `0x01` | `0xFFFFFFFE` | application-defined metadata bytes |
| data i | `0x02` | `i` | plaintext bytes of chunk i |

~~~
nonce = nonce_prefix[8 bytes] || uint32_be(counter)
~~~

Valid data indices are `0..0xFFFFFFFD`. The record kind has one byte and
the counter has four bytes in both key derivation and AAD. A header
record's ciphertext is empty, so only its 16-byte tag is stored at offset
48. Explicitly present empty metadata still stores a 16-byte tag.

Every encryption MUST generate a fresh cryptographically random 16-byte
salt and a fresh 8-byte nonce prefix. This includes retries that perform
encryption again, metadata edits, changed data, changed keys, and changed
header fields. Batch writers MUST NOT deliberately reuse a salt to avoid
KDF work: default HKDF mode has no expensive per-file password derivation.

No `(record_key, nonce)` pair may be reused for a new encryption. A
container is an immutable snapshot. Updating an existing record in place
under the original salt and prefix is not a supported operation. Copying
or retrying upload of the exact existing ciphertext is allowed because
it performs no new encryption. Fixed fixture randomness is for tests only.

A derived AES key encrypts one bounded record: at most `2 ** 26` data
bytes, 65,519 metadata bytes, or the empty header plaintext. This avoids
deliberately using one data AES key for all chunks or an entire collection.

## 5. Authentication inputs

For every record, with the `H` and `R` defined in section 3.3:

~~~
AAD = H || R
record = AES-256-GCM-Encrypt(record_key, nonce, plaintext, AAD)
~~~

AAD has exactly 53 bytes: the 48 header bytes, one record-kind byte,
and four big-endian counter bytes. It includes the format version, KDF
mode and rounds, lengths, key hint, salt, and nonce prefix through `H`.

| Record | Plaintext | Associated data |
| --- | --- | --- |
| header | empty byte string | `H || 0x00 || uint32_be(0xFFFFFFFF)` |
| metadata | application-defined metadata bytes | `H || 0x01 || uint32_be(0xFFFFFFFE)` |
| data i | plaintext bytes of chunk i | `H || 0x02 || uint32_be(i)` |

The `header_tag` is the 16-byte result of encrypting an empty plaintext
with the header record key, nonce, and AAD. Metadata uses its own derived
record key and binds the complete header context. All three record kinds
use the same derivation and authentication construction.

A writer can calculate `metadata_size` before encryption as
`len(metadata) + 16`. There is no length/authentication dependency cycle.
The writer finalizes `H`, then derives record keys and encrypts the header,
metadata, and data. v1's empty metadata AAD MUST NOT be used for v2.

Each record MUST be authenticated before its plaintext is returned.
Wrong secrets, modified header tags, and modified record tags MUST
cause authentication failure. A reader MUST NOT return partially decrypted
bytes from a record whose authentication failed.

Opening a container authenticates its header, not unread records.
Random-access readers authenticate only the records they actually read.
Whole-container verification requires checking the total length, all data
records, and any metadata. Whole-container decryptors MUST publish their
final output only after successful completion. A streaming decryptor MAY
write verified records to a temporary destination, but MUST discard or
explicitly invalidate that partial destination on failure.

## 6. Opening and seeking

A reader MUST perform these steps in order:

1. Read exactly 64 header bytes and validate magic, version, flags,
   parameter combinations, record counts, size arithmetic, and available
   total length.
2. Apply local resource limits and require an input of the correct type:
   raw key bytes for mode `2`, or Unicode password for mode `1`. Reject
   a type mismatch before running a password KDF. A public `key_id` MAY
   select candidate credentials but does not authenticate them.
3. Derive `IKM`, `PRK`, and the header record key, then authenticate the
   header tag before treating fields as trusted or returning plaintext.
4. For each requested record, read its exact ciphertext length, derive
   its record key, and authenticate it before returning its plaintext.

An authentication failure MUST NOT cause a retry using another version,
KDF mode, password encoding, AAD construction, or shortened tag. Trying
explicitly supplied credentials of the same declared mode is allowed.

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

The physical offsets, tag overhead, and chunk sizes are the same as v1.
HTTP request coalescing, prefetch, caching, and playback buffering are
reader or transport choices; they MUST NOT change record boundaries.

## 7. Metadata, object naming, and scope

Metadata is an opaque byte string with a maximum plaintext length of
65,519 bytes. Applications MAY define a UTF-8 JSON convention, but the
container does not require JSON, filenames, music tags, or any media type.

The format works with local seekable files and remote byte-range sources.
Authentication is independent of HTTP, S3, directory indexing, and
application account management. Implementations must validate the actual
range lengths supplied by their byte source.

Applications SHOULD keep identifying filenames and tags in encrypted
metadata or an encrypted catalog. Remote object names SHOULD use random
identifiers or a hash of the complete ciphertext. Publishing the raw
plaintext hash, original filename, or a plaintext catalog can reveal a
match without decrypting a container. Local plaintext-based deduplication
is an application choice; its identifying index should remain private.

Master keys and passwords MUST NOT be published in plaintext alongside
the stored containers, including through filenames, headers, public
indexes, or shared URLs. Client key backup and transfer are separate
application responsibilities.

The container reveals its original size, chunk size, KDF parameters,
key identifier, and whether metadata is present. It does not provide
availability, compression, version rollback protection, or protection
against an attacker replacing the complete file with another valid file.
It does not hide the `CSEA` format identifier, object existence, access
patterns, or sharing activity. Protecting a compromised client or
revoking access to previously obtained secrets is outside this profile.

## 8. Version compatibility and migration

Readers supporting both versions MUST dispatch by exact `CSEA` magic and
the version byte. v1 uses the rules in [SPEC-V1.md](SPEC-V1.md), including
direct PBKDF2-to-AES derivation and empty metadata AAD. v2 uses this
document, including HKDF in both modes and per-record keys. Unsupported
versions MUST be rejected. File extensions are not version selectors.

Existing v1 files remain v1. Changing the version byte, KDF ID, or rounds
does not migrate a file and breaks authentication. A migration MUST read
and authenticate the old metadata and all data records, write a new v2
container with fresh salt and prefix, then fully verify the new container
before replacing the old object or updating caller references. A temporary
destination can avoid storing the entire plaintext in memory or publishing
an intermediate plaintext file. Failed migration MUST preserve the original.

The writer must explicitly select the new secret type. An old password
is not automatically a random master key even if it looks hexadecimal.
Applications that know an old 32-character hex value was a generated
16-byte random secret MAY explicitly decode and reuse those secret bytes
for v2 mode `2`; otherwise generate a fresh random master key or choose
password mode. Old files continue to use the original password text.

See [MIGRATION.md](MIGRATION.md) for dispatch and migration guidance.

## 9. Draft vectors and implementation status

[test-vectors/v2.properties](test-vectors/v2.properties) contains the
draft known-answer vectors. Byte-valued fields use hexadecimal ASCII;
`-` means absent metadata, while an empty value means present but empty
metadata. A vector supplies exactly one secret type: `master_key_hex`
for mode `2` or `password_utf8_hex` for mode `1`.

Vectors include `IKM`, `PRK`, header and metadata keys where applicable,
each data record key, AAD, complete header and ciphertext, and expected
plaintext and metadata. They cover 16- and 32-byte raw keys, empty files,
absent and empty metadata, binary metadata, a chunk boundary, and a Unicode
password. Fixed salts, prefixes, and low password round counts are for
tests only and MUST NOT be copied into normal writers.

The v1 fixed vectors in `test-vectors/v1.properties` remain unchanged.
The packaged Python and Java reference implementations provide separate v1 and
v2 draft APIs, and `tools/check.sh` exercises both, including two-way
interoperability in both v2 modes. Draft-vector verification is recorded
separately in [VALIDATION.md](VALIDATION.md); it is not an application playback
test or a completed cryptographic audit.

Run the independent Python and Java draft-vector calculations with:

~~~sh
CHUNKSEAL_PYTHON=python3 bash tools/check-v2-vectors.sh
~~~

The tools compare exact keys, AAD, and ciphertexts and check record
authentication and selected cross-chunk reads. They are vector-review
helpers, not general v2 container APIs.

Before a v2 implementation is declared conforming, it must reproduce
the v2 fixed vectors and pass two-way interoperability, random and
cross-chunk reads, wrong and mistyped secrets, malformed and over-cost
headers, record substitution and reordering, tampering, truncation,
trailing bytes, Unicode encoding, and counter/offset boundary checks.

## 10. Cryptographic references

- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html): HKDF,
  instantiated with HMAC-SHA256 and the exact context bytes in section 3.3.
- [RFC 5116 section 5.2](https://www.rfc-editor.org/rfc/rfc5116.html#section-5.2):
  AES-256-GCM with a 12-byte nonce and 16-byte tag.
- [RFC 8018 section 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2):
  PBKDF2 for the optional password mode, instantiated with HMAC-SHA256.

Protocol code and documentation: AGPL-3.0-only; see `LICENSE` and `NOTICE`.
Additional GPLv3 permission: [ADDITIONAL-PERMISSION.md](ADDITIONAL-PERMISSION.md).
