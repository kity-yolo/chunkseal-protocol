# Legacy container migration

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

## Conversion procedure

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

The new reference reader accepts only `CSEA`. Applications that must keep reading legacy files
can explicitly dispatch to the legacy and new readers based on the header; do not let a single
reader ignore or loosely match the file identifier.

The standalone reference reader in this repository accepts only `CSEA`.
