# Container version dispatch and migration

The latest [specification](SPEC.md) is the v2 draft. The standalone Python / Java
package implements ChunkSeal v1 and the v2 draft. Application integrations track
their v2 rollout separately. The v2 procedures below apply to a v2
implementation; this documentation does not convert any existing file.

## Exact dispatch

| Magic | Version | Reader rules |
| --- | --- | --- |
| `NCMX` | `1` | Explicit application legacy reader |
| `CSEA` | `1` | [SPEC-V1.md](SPEC-V1.md): direct PBKDF2 key, empty metadata AAD |
| `CSEA` | `2` | [SPEC.md](SPEC.md): typed raw key or password, HKDF per record, header-bound AAD |
| Other magic or unsupported version | any | Reject |

Extensions do not choose the format or version. Do not fall back to another
version, mode, encoding, or authentication rule after authentication fails.
Old readers must reject `CSEA` version `2`; a new reader retains v1 support
by dispatching to the original v1 rules, not by weakening v2 validation.

## ChunkSeal v1 to v2

v2 retains the 64-byte header and physical record offsets, but changes the
version byte, key derivation, and authentication inputs. Changing a version
byte, setting `rounds` to zero, or changing `kdf_id` does not convert a file.
Even v2 password mode adds HKDF and per-record keys; it cannot reuse v1 tags.

1. Open the v1 container using the original password text and exact v1 rules.
2. Explicitly select a v2 secret: a random 16- or 32-byte master key for the
   default mode, or a human-chosen password for optional password mode.
3. Authenticate the old metadata and every data record while writing a new
   temporary v2 container with fresh random salt and nonce prefix. A streaming
   pipeline avoids holding the complete plaintext in memory or publishing it
   as an intermediate file.
4. Verify the new container's length, header, metadata, and all data records,
   and compare the recovered plaintext and metadata with the original.
5. Publish the new object and update path, key, and version references only
   after both old and new containers have been fully verified. Preserve the
   old object if any step fails.

If an application knows its old 32-character hexadecimal credential came
from 16 cryptographically random bytes, it may explicitly decode those bytes
for v2 raw-key mode. This decision must use known credential provenance,
not merely the string's shape. A manually chosen hex-looking password must
continue to be treated as a password. Existing v1 files always use the
original text encoding and original derivation rounds.

For password-based collection access, an application may protect a master
key once in a separate authenticated key export and use that raw master key
for each v2 file. This avoids a password KDF for every file. Existing direct
password-mode files retain their per-file derivation cost. This draft does
not add in-place key rotation or mutable key slots; changing the encryption
secret regenerates the container.

Use new random object names or ciphertext-derived names for newly encrypted
objects, rather than replacing cached bytes under the old immutable name.
Do not expose the original filename or plaintext hash through the new path.

## Legacy NCMX to ChunkSeal v1

ChunkSeal gives the original custom chunked container an independent name and a formal
specification. The original container is called NCMX, a format the application defined for itself;
it has a different layout and purpose from NetEase's NCM file format.

| Item | Legacy container | ChunkSeal v1 |
| --- | --- | --- |
| Name | NCMX | ChunkSeal |
| First 4 header bytes | `NCMX` | `CSEA` |
| Suggested extension | `.ncmx` | `.cseal` |
| Encryption and derivation | AES-256-GCM / PBKDF2-HMAC-SHA256 | Same as legacy |
| Body layout | 64-byte header + optional metadata + data chunks | Same as legacy |

### Conversion procedure

1. Verify and read the original file with the legacy container reader.
2. Regenerate the container with the ChunkSeal writer, using a fresh random salt and nonce
   prefix.
3. Verify the metadata and all data chunks of the new file.
4. Only then publish the new file or replace the legacy file, and update path references in
   callers.

Changing the extension alone does not change the file format. Replacing `NCMX` in the header
with `CSEA` directly would break authentication of the header and data chunks: those bytes are
part of their associated data, so the authentication tags must be recomputed. The reference
migration procedure re-encrypts after full verification, avoiding any bypass of authentication
checks.

The v1 reference reader accepts only `CSEA` version `1`. Applications that must keep reading legacy files
can explicitly dispatch to the legacy and new readers based on the header; do not let a single
reader ignore or loosely match the file identifier.

Each standalone reference reader accepts only its own version: the v1 reader only
`CSEA` version `1`, the v2 reader only version `2`. Python's `chunkseal.open_reader`
dispatches between them by exact magic and version byte. See
[ADDITIONAL-PERMISSION.md](ADDITIONAL-PERMISSION.md) for GPLv3 integration into
[Tingyu](https://github.com/qiuyuxc/tingyu);
the default license for code and documentation remains AGPLv3.
