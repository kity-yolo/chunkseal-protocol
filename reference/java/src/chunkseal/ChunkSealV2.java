// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ChunkSeal contributors
// Additional GPLv3 permission: see ADDITIONAL-PERMISSION.md.
package chunkseal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Independent JDK reference for the v2 draft container specified in SPEC.md. */
public final class ChunkSealV2 {
    public static final int VERSION = 2;
    private static final byte[] LABEL =
        "ChunkSeal/v2/record-key\0".getBytes(StandardCharsets.US_ASCII);
    private static final int HEADER_KIND = 0;
    private static final int METADATA_KIND = 1;
    private static final int DATA_KIND = 2;
    private static final long HEADER_COUNTER = 0xFFFFFFFFL;
    private static final long METADATA_COUNTER = 0xFFFFFFFEL;

    private ChunkSealV2() {}

    /** Parsed fields are untrusted until a Reader verifies their header tag. */
    public static final class Header {
        public final int flags;
        public final int chunkLog2;
        public final int kdfId;
        public final int rounds;
        public final int metadataSize;
        public final int keyId;
        public final long plaintextSize;
        private final byte[] salt;
        private final byte[] prefix;
        private final byte[] aad;
        private final byte[] tag;

        private Header(byte[] bytes) throws ChunkSeal.FormatException {
            if (bytes.length != ChunkSeal.HEADER_SIZE) {
                throw new ChunkSeal.FormatException("A header must contain exactly 64 bytes");
            }
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            byte[] magic = new byte[4];
            buffer.get(magic);
            if (!Arrays.equals(magic, "CSEA".getBytes(StandardCharsets.US_ASCII))) {
                throw new ChunkSeal.FormatException("Unsupported file magic");
            }
            if (Byte.toUnsignedInt(buffer.get()) != VERSION) {
                throw new ChunkSeal.FormatException("Unsupported version");
            }
            flags = Byte.toUnsignedInt(buffer.get());
            chunkLog2 = Byte.toUnsignedInt(buffer.get());
            kdfId = Byte.toUnsignedInt(buffer.get());
            rounds = buffer.getInt();
            metadataSize = Short.toUnsignedInt(buffer.getShort());
            keyId = Short.toUnsignedInt(buffer.getShort());
            salt = new byte[16];
            prefix = new byte[8];
            buffer.get(salt).get(prefix);
            plaintextSize = buffer.getLong();
            validateFields(flags, chunkLog2, kdfId, rounds, metadataSize, keyId, plaintextSize);
            aad = Arrays.copyOf(bytes, ChunkSeal.AAD_SIZE);
            tag = Arrays.copyOfRange(bytes, ChunkSeal.AAD_SIZE, ChunkSeal.HEADER_SIZE);
        }

        public byte[] salt() { return salt.clone(); }
        public byte[] noncePrefix() { return prefix.clone(); }
        public int chunkSize() { return 1 << chunkLog2; }
        public long chunkCount() {
            return (plaintextSize + chunkSize() - 1) / chunkSize();
        }
        public long fileSize() {
            return ChunkSeal.HEADER_SIZE + (long) metadataSize + plaintextSize
                + ChunkSeal.TAG_SIZE * chunkCount();
        }
        public long chunkOffset(long index) throws ChunkSeal.FormatException {
            if (index < 0 || index >= chunkCount()) {
                throw new ChunkSeal.FormatException("Data chunk index outside container");
            }
            return ChunkSeal.HEADER_SIZE + (long) metadataSize
                + index * (chunkSize() + (long) ChunkSeal.TAG_SIZE);
        }
    }

    public static Header parseHeader(byte[] bytes) throws ChunkSeal.FormatException {
        return new Header(bytes);
    }

    private static void validateFields(int flags, int log2, int kdfId, int rounds, int metaSize,
                                       int keyId, long size) throws ChunkSeal.FormatException {
        if (log2 < 12 || log2 > 26) {
            throw new ChunkSeal.FormatException("chunkLog2 must be in 12..26");
        }
        if (kdfId == 2) {
            if (rounds != 0) throw new ChunkSeal.FormatException("Random-key mode requires zero rounds");
        } else if (kdfId == 1) {
            if (rounds < 1) throw new ChunkSeal.FormatException("PBKDF2 rounds outside supported range");
        } else {
            throw new ChunkSeal.FormatException("Unsupported KDF");
        }
        if (keyId < 0 || keyId > 0xFFFF) throw new ChunkSeal.FormatException("keyId outside 0..65535");
        if (flags != 0 && flags != 1) throw new ChunkSeal.FormatException("Unsupported flag bits");
        if ((flags == 0 && metaSize != 0) ||
            (flags == 1 && (metaSize < ChunkSeal.TAG_SIZE || metaSize > 0xFFFF))) {
            throw new ChunkSeal.FormatException("Inconsistent metadata flag or length");
        }
        if (size < 0 || size > ChunkSeal.MAX_CHUNKS * (1L << log2)) {
            throw new ChunkSeal.FormatException("Plaintext size overlaps reserved nonce counters");
        }
    }

    private static byte[] masterKeyBytes(byte[] masterKey) throws ChunkSeal.FormatException {
        if (masterKey == null || (masterKey.length != 16 && masterKey.length != 32)) {
            throw new ChunkSeal.FormatException("A master key must contain exactly 16 or 32 bytes");
        }
        return masterKey.clone();
    }

    private static byte[] passwordIkm(String password, byte[] salt, int rounds)
            throws ChunkSeal.FormatException {
        if (password == null) throw new ChunkSeal.FormatException("Password must not be null");
        try {
            StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(password));
        } catch (CharacterCodingException error) {
            throw new ChunkSeal.FormatException("Password must be well-formed Unicode", error);
        }
        PBEKeySpec specification = new PBEKeySpec(password.toCharArray(), salt, rounds, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(specification).getEncoded();
        } catch (GeneralSecurityException error) {
            throw new ChunkSeal.FormatException("PBKDF2 provider failure", error);
        } finally {
            specification.clearPassword();
        }
    }

    private static byte[] hmac(byte[] key, byte[] message) throws ChunkSeal.FormatException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException error) {
            throw new ChunkSeal.FormatException("HMAC provider failure", error);
        }
    }

    private static byte[] recordId(int kind, long counter) {
        return ByteBuffer.allocate(5).order(ByteOrder.BIG_ENDIAN)
            .put((byte) kind).putInt((int) counter).array();
    }

    private static byte[] recordKey(byte[] prk, byte[] headerAad, int kind, long counter)
            throws ChunkSeal.FormatException {
        byte[] id = recordId(kind, counter);
        byte[] info = ByteBuffer.allocate(LABEL.length + headerAad.length + id.length + 1)
            .put(LABEL).put(headerAad).put(id).put((byte) 1).array();
        return hmac(prk, info);
    }

    private static byte[] nonce(byte[] prefix, long counter) {
        return ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
            .put(prefix).putInt((int) counter).array();
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce,
                               byte[] aad, byte[] input) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (AEADBadTagException error) {
            throw new ChunkSeal.AuthenticationException("Record authentication failed", error);
        } catch (GeneralSecurityException error) {
            throw new ChunkSeal.FormatException("AES-GCM provider failure", error);
        }
    }

    private static byte[] exactRange(ChunkSeal.Source source, long offset, int length)
            throws IOException {
        byte[] result = source.readAt(offset, length);
        if (result == null || result.length != length) {
            throw new ChunkSeal.FormatException("Source range length does not match request");
        }
        return result;
    }

    public static final class Reader {
        private final ChunkSeal.Source source;
        private final Header header;
        private final byte[] prk;

        public Reader(ChunkSeal.Source source, byte[] masterKey) throws IOException {
            this.source = source;
            header = parseHeader(exactRange(source, 0, ChunkSeal.HEADER_SIZE));
            if (source.size() != header.fileSize()) {
                throw new ChunkSeal.FormatException("Container is truncated or has trailing bytes");
            }
            if (header.kdfId != 2) {
                throw new ChunkSeal.FormatException("Container requires a password, not a raw master key");
            }
            byte[] ikm = masterKeyBytes(masterKey);
            prk = hmac(header.salt, ikm);
            authenticateHeader();
        }

        public Reader(ChunkSeal.Source source, String password) throws IOException {
            this(source, password, ChunkSeal.DEFAULT_MAX_ROUNDS);
        }

        public Reader(ChunkSeal.Source source, String password, int maxRounds) throws IOException {
            this.source = source;
            header = parseHeader(exactRange(source, 0, ChunkSeal.HEADER_SIZE));
            if (source.size() != header.fileSize()) {
                throw new ChunkSeal.FormatException("Container is truncated or has trailing bytes");
            }
            if (header.kdfId != 1) {
                throw new ChunkSeal.FormatException("Container requires a raw master key, not a password");
            }
            if (maxRounds < 1 || header.rounds > maxRounds) {
                throw new ChunkSeal.FormatException("PBKDF2 rounds exceed reader policy");
            }
            byte[] ikm = passwordIkm(password, header.salt, header.rounds);
            prk = hmac(header.salt, ikm);
            authenticateHeader();
        }

        private void authenticateHeader() throws IOException {
            byte[] key = recordKey(prk, header.aad, HEADER_KIND, HEADER_COUNTER);
            byte[] aad = concat(header.aad, recordId(HEADER_KIND, HEADER_COUNTER));
            crypt(Cipher.DECRYPT_MODE, key, nonce(header.prefix, HEADER_COUNTER), aad, header.tag);
        }

        public Header header() { return header; }

        public byte[] metadata() throws IOException {
            if (header.flags == 0) return null;
            byte[] record = exactRange(source, ChunkSeal.HEADER_SIZE, header.metadataSize);
            byte[] key = recordKey(prk, header.aad, METADATA_KIND, METADATA_COUNTER);
            byte[] aad = concat(header.aad, recordId(METADATA_KIND, METADATA_COUNTER));
            return crypt(Cipher.DECRYPT_MODE, key, nonce(header.prefix, METADATA_COUNTER),
                         aad, record);
        }

        public byte[] readChunk(long index) throws IOException {
            long offset = header.chunkOffset(index);
            int length = (int) Math.min(header.chunkSize(),
                header.plaintextSize - index * header.chunkSize());
            byte[] record = exactRange(source, offset, length + ChunkSeal.TAG_SIZE);
            byte[] key = recordKey(prk, header.aad, DATA_KIND, index);
            byte[] aad = concat(header.aad, recordId(DATA_KIND, index));
            return crypt(Cipher.DECRYPT_MODE, key, nonce(header.prefix, index), aad, record);
        }

        public byte[] read(long offset, int length) throws IOException {
            if (offset < 0 || length < 0 || offset > header.plaintextSize - length) {
                throw new ChunkSeal.FormatException("Requested range outside plaintext");
            }
            if (length == 0) return new byte[0];
            byte[] result = new byte[length];
            long first = offset / header.chunkSize();
            long last = (offset + length - 1) / header.chunkSize();
            int written = 0;
            for (long index = first; index <= last; index++) {
                byte[] block = readChunk(index);
                long base = index * header.chunkSize();
                int from = (int) Math.max(0, offset - base);
                int to = (int) Math.min(block.length, offset + length - base);
                System.arraycopy(block, from, result, written, to - from);
                written += to - from;
            }
            return result;
        }

        /** Discard a partial destination if any record fails verification. */
        public void decryptTo(OutputStream destination) throws IOException {
            metadata();
            for (long index = 0; index < header.chunkCount(); index++) {
                destination.write(readChunk(index));
            }
        }
    }

    private static byte[] concat(byte[] first, byte[] second) {
        return ByteBuffer.allocate(first.length + second.length).put(first).put(second).array();
    }

    public static byte[] encrypt(byte[] plaintext, byte[] masterKey, byte[] metadata,
                                 int log2, int keyId) throws IOException {
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        encrypt(new ByteArrayInputStream(plaintext), destination, plaintext.length,
                masterKey, metadata, log2, keyId);
        return destination.toByteArray();
    }

    /** Writes a fresh container. The caller must discard destination on failure. */
    public static void encrypt(InputStream source, OutputStream destination, long plaintextSize,
                               byte[] masterKey, byte[] metadata, int log2, int keyId)
            throws IOException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] prefix = new byte[8];
        random.nextBytes(salt);
        random.nextBytes(prefix);
        encryptWithParameters(source, destination, plaintextSize, masterKeyBytes(masterKey), null,
                              metadata, log2, 0, keyId, salt, prefix);
    }

    public static byte[] encrypt(byte[] plaintext, String password, byte[] metadata,
                                 int log2, int rounds, int keyId) throws IOException {
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        encrypt(new ByteArrayInputStream(plaintext), destination, plaintext.length,
                password, metadata, log2, rounds, keyId);
        return destination.toByteArray();
    }

    /** Writes a fresh container. The caller must discard destination on failure. */
    public static void encrypt(InputStream source, OutputStream destination, long plaintextSize,
                               String password, byte[] metadata, int log2, int rounds,
                               int keyId) throws IOException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] prefix = new byte[8];
        random.nextBytes(salt);
        random.nextBytes(prefix);
        encryptWithParameters(source, destination, plaintextSize, null, password, metadata,
                              log2, rounds, keyId, salt, prefix);
    }

    /** Package-private deterministic entry points exclusively for fixtures. */
    static byte[] encryptDeterministic(byte[] plaintext, byte[] masterKey, byte[] metadata,
                                      int log2, int keyId, byte[] salt, byte[] prefix)
            throws IOException {
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        encryptWithParameters(new ByteArrayInputStream(plaintext), destination, plaintext.length,
                              masterKeyBytes(masterKey), null, metadata, log2, 0, keyId,
                              salt, prefix);
        return destination.toByteArray();
    }

    static byte[] encryptDeterministic(byte[] plaintext, String password, byte[] metadata,
                                      int log2, int rounds, int keyId, byte[] salt, byte[] prefix)
            throws IOException {
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        encryptWithParameters(new ByteArrayInputStream(plaintext), destination, plaintext.length,
                              null, password, metadata, log2, rounds, keyId, salt, prefix);
        return destination.toByteArray();
    }

    private static void encryptWithParameters(InputStream source, OutputStream destination,
                                              long size, byte[] masterKey, String password,
                                              byte[] metadata, int log2, int rounds, int keyId,
                                              byte[] salt, byte[] prefix) throws IOException {
        if (metadata != null && metadata.length > 0xFFFF - ChunkSeal.TAG_SIZE) {
            throw new ChunkSeal.FormatException("Metadata too long");
        }
        int metaSize = metadata == null ? 0 : metadata.length + ChunkSeal.TAG_SIZE;
        int flags = metadata == null ? 0 : 1;
        int kdfId = masterKey != null ? 2 : 1;
        validateFields(flags, log2, kdfId, rounds, metaSize, keyId, size);
        if (salt.length != 16 || prefix.length != 8) {
            throw new ChunkSeal.FormatException("Invalid salt or nonce prefix length");
        }
        byte[] headerAad = ByteBuffer.allocate(ChunkSeal.AAD_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .put("CSEA".getBytes(StandardCharsets.US_ASCII)).put((byte) VERSION)
            .put((byte) flags).put((byte) log2).put((byte) kdfId)
            .putInt(rounds).putShort((short) metaSize).putShort((short) keyId)
            .put(salt).put(prefix).putLong(size).array();
        byte[] ikm = masterKey != null ? masterKey : passwordIkm(password, salt, rounds);
        byte[] prk = hmac(salt, ikm);
        destination.write(headerAad);
        byte[] headerKey = recordKey(prk, headerAad, HEADER_KIND, HEADER_COUNTER);
        byte[] headerRecordAad = concat(headerAad, recordId(HEADER_KIND, HEADER_COUNTER));
        destination.write(crypt(Cipher.ENCRYPT_MODE, headerKey, nonce(prefix, HEADER_COUNTER),
                                headerRecordAad, new byte[0]));
        if (metadata != null) {
            byte[] key = recordKey(prk, headerAad, METADATA_KIND, METADATA_COUNTER);
            byte[] aad = concat(headerAad, recordId(METADATA_KIND, METADATA_COUNTER));
            destination.write(crypt(Cipher.ENCRYPT_MODE, key, nonce(prefix, METADATA_COUNTER),
                                    aad, metadata));
        }
        long remaining = size;
        long index = 0;
        while (remaining > 0) {
            int count = (int) Math.min(1 << log2, remaining);
            byte[] block = readExactly(source, count);
            byte[] key = recordKey(prk, headerAad, DATA_KIND, index);
            byte[] aad = concat(headerAad, recordId(DATA_KIND, index));
            destination.write(crypt(Cipher.ENCRYPT_MODE, key, nonce(prefix, index), aad, block));
            remaining -= count;
            index++;
        }
        if (source.read() != -1) throw new ChunkSeal.FormatException("Source exceeds plaintextSize");
    }

    private static byte[] readExactly(InputStream stream, int length) throws IOException {
        byte[] result = new byte[length];
        int received = 0;
        while (received < length) {
            int count = stream.read(result, received, length - received);
            if (count < 0) throw new ChunkSeal.FormatException("Truncated input");
            if (count == 0) {
                int one = stream.read();
                if (one < 0) throw new ChunkSeal.FormatException("Truncated input");
                result[received++] = (byte) one;
            } else {
                received += count;
            }
        }
        return result;
    }
}