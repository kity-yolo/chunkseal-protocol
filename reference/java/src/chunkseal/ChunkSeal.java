// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ChunkSeal contributors
package chunkseal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
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
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Independent JDK reference for the container specified in SPEC.md. */
public final class ChunkSeal {
    public static final int VERSION = 1;
    public static final int HEADER_SIZE = 64;
    public static final int AAD_SIZE = 48;
    public static final int TAG_SIZE = 16;
    public static final int DEFAULT_CHUNK_LOG2 = 20;
    public static final int DEFAULT_ROUNDS = 600_000;
    public static final int DEFAULT_MAX_ROUNDS = 2_000_000;
    public static final long MAX_CHUNKS = 0xFFFFFFFEL;
    private static final byte[] MAGIC = "CSEA".getBytes(StandardCharsets.US_ASCII);
    private static final long HEADER_COUNTER = 0xFFFFFFFFL;
    private static final long METADATA_COUNTER = 0xFFFFFFFEL;

    private ChunkSeal() {}

    public static class FormatException extends IOException {
        private static final long serialVersionUID = 1L;
        public FormatException(String message) { super(message); }
        public FormatException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class AuthenticationException extends FormatException {
        private static final long serialVersionUID = 1L;
        public AuthenticationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Access to one source instance must be serialized by the caller. */
    public interface Source {
        long size() throws IOException;
        byte[] readAt(long offset, int length) throws IOException;
    }

    public static Source bytesSource(byte[] bytes) {
        byte[] data = bytes.clone();
        return new Source() {
            @Override public long size() { return data.length; }
            @Override public byte[] readAt(long offset, int length) throws IOException {
                if (offset < 0 || length < 0 || offset > data.length - (long) length) {
                    throw new FormatException("Source range outside container");
                }
                return Arrays.copyOfRange(data, (int) offset, (int) offset + length);
            }
        };
    }

    /** The caller retains ownership of, and must close, the file. */
    public static Source fileSource(RandomAccessFile file) {
        return new Source() {
            @Override public long size() throws IOException { return file.length(); }
            @Override public byte[] readAt(long offset, int length) throws IOException {
                if (offset < 0 || length < 0) {
                    throw new FormatException("Negative source range");
                }
                byte[] data = new byte[length];
                file.seek(offset);
                file.readFully(data);
                return data;
            }
        };
    }

    /** Parsed fields are untrusted until a Reader verifies their header tag. */
    public static final class Header {
        public final int flags;
        public final int chunkLog2;
        public final int rounds;
        public final int metadataSize;
        public final int keyId;
        public final long plaintextSize;
        private final byte[] salt;
        private final byte[] prefix;
        private final byte[] aad;
        private final byte[] tag;

        private Header(byte[] bytes) throws FormatException {
            if (bytes.length != HEADER_SIZE) {
                throw new FormatException("A header must contain exactly 64 bytes");
            }
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            byte[] magic = new byte[4];
            buffer.get(magic);
            if (!Arrays.equals(magic, MAGIC)) throw new FormatException("Unsupported file magic");
            if (Byte.toUnsignedInt(buffer.get()) != VERSION) {
                throw new FormatException("Unsupported version");
            }
            flags = Byte.toUnsignedInt(buffer.get());
            chunkLog2 = Byte.toUnsignedInt(buffer.get());
            if (Byte.toUnsignedInt(buffer.get()) != 1) throw new FormatException("Unsupported KDF");
            rounds = buffer.getInt();
            metadataSize = Short.toUnsignedInt(buffer.getShort());
            keyId = Short.toUnsignedInt(buffer.getShort());
            salt = new byte[16];
            prefix = new byte[8];
            buffer.get(salt).get(prefix);
            plaintextSize = buffer.getLong();
            validateFields(flags, chunkLog2, rounds, metadataSize, keyId, plaintextSize);
            aad = Arrays.copyOf(bytes, AAD_SIZE);
            tag = Arrays.copyOfRange(bytes, AAD_SIZE, HEADER_SIZE);
        }

        public byte[] salt() { return salt.clone(); }
        public byte[] noncePrefix() { return prefix.clone(); }
        public int chunkSize() { return 1 << chunkLog2; }
        public long chunkCount() {
            return (plaintextSize + chunkSize() - 1) / chunkSize();
        }
        public long fileSize() {
            return HEADER_SIZE + (long) metadataSize + plaintextSize + TAG_SIZE * chunkCount();
        }
        public long chunkOffset(long index) throws FormatException {
            if (index < 0 || index >= chunkCount()) {
                throw new FormatException("Data chunk index outside container");
            }
            return HEADER_SIZE + (long) metadataSize + index * (chunkSize() + (long) TAG_SIZE);
        }
    }

    public static Header parseHeader(byte[] bytes) throws FormatException {
        return new Header(bytes);
    }

    private static void validateFields(int flags, int log2, int rounds, int metaSize,
                                       int keyId, long size) throws FormatException {
        if (log2 < 12 || log2 > 26) throw new FormatException("chunkLog2 must be in 12..26");
        if (rounds < 1) throw new FormatException("PBKDF2 rounds outside supported range");
        if (keyId < 0 || keyId > 0xFFFF) throw new FormatException("keyId outside 0..65535");
        if (flags != 0 && flags != 1) throw new FormatException("Unsupported flag bits");
        if ((flags == 0 && metaSize != 0) ||
            (flags == 1 && (metaSize < TAG_SIZE || metaSize > 0xFFFF))) {
            throw new FormatException("Inconsistent metadata flag or length");
        }
        if (size < 0 || size > MAX_CHUNKS * (1L << log2)) {
            throw new FormatException("Plaintext size overlaps reserved nonce counters");
        }
    }

    public static byte[] deriveKey(String password, byte[] salt, int rounds)
            throws FormatException {
        if (salt.length != 16 || rounds < 1) throw new FormatException("Invalid PBKDF2 parameters");
        try {
            StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(password));
        } catch (CharacterCodingException error) {
            throw new FormatException("Password must be well-formed Unicode", error);
        }
        PBEKeySpec specification = new PBEKeySpec(password.toCharArray(), salt, rounds, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(specification).getEncoded();
        } catch (GeneralSecurityException error) {
            throw new FormatException("PBKDF2 provider failure", error);
        } finally {
            specification.clearPassword();
        }
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
            if (aad != null && aad.length != 0) cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (AEADBadTagException error) {
            throw new AuthenticationException("Record authentication failed", error);
        } catch (GeneralSecurityException error) {
            throw new FormatException("AES-GCM provider failure", error);
        }
    }

    private static byte[] exactRange(Source source, long offset, int length) throws IOException {
        byte[] result = source.readAt(offset, length);
        if (result == null || result.length != length) {
            throw new FormatException("Source range length does not match request");
        }
        return result;
    }

    public static final class Reader {
        private final Source source;
        private final Header header;
        private final byte[] key;

        public Reader(Source source, String password) throws IOException {
            this(source, password, DEFAULT_MAX_ROUNDS);
        }

        public Reader(Source source, String password, int maxRounds) throws IOException {
            this.source = source;
            header = parseHeader(exactRange(source, 0, HEADER_SIZE));
            if (source.size() != header.fileSize()) {
                throw new FormatException("Container is truncated or has trailing bytes");
            }
            if (maxRounds < 1 || header.rounds > maxRounds) {
                throw new FormatException("PBKDF2 rounds exceed reader policy");
            }
            key = deriveKey(password, header.salt, header.rounds);
            crypt(Cipher.DECRYPT_MODE, key, nonce(header.prefix, HEADER_COUNTER),
                  header.aad, header.tag);
        }

        public Header header() { return header; }

        public byte[] metadata() throws IOException {
            if (header.flags == 0) return null;
            byte[] record = exactRange(source, HEADER_SIZE, header.metadataSize);
            return crypt(Cipher.DECRYPT_MODE, key, nonce(header.prefix, METADATA_COUNTER),
                         null, record);
        }

        public byte[] readChunk(long index) throws IOException {
            long offset = header.chunkOffset(index);
            int length = (int) Math.min(header.chunkSize(),
                header.plaintextSize - index * header.chunkSize());
            byte[] record = exactRange(source, offset, length + TAG_SIZE);
            return crypt(Cipher.DECRYPT_MODE, key, nonce(header.prefix, index), header.aad, record);
        }

        public byte[] read(long offset, int length) throws IOException {
            if (offset < 0 || length < 0 || offset > header.plaintextSize - length) {
                throw new FormatException("Requested range outside plaintext");
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
        encryptWithParameters(source, destination, plaintextSize, password, metadata,
                              log2, rounds, keyId, salt, prefix);
    }

    /** Package-private deterministic entry point exclusively for fixtures. */
    static byte[] encryptDeterministic(byte[] plaintext, String password, byte[] metadata,
                                      int log2, int rounds, int keyId, byte[] salt,
                                      byte[] prefix) throws IOException {
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        encryptWithParameters(new ByteArrayInputStream(plaintext), destination, plaintext.length,
                              password, metadata, log2, rounds, keyId, salt, prefix);
        return destination.toByteArray();
    }

    private static void encryptWithParameters(InputStream source, OutputStream destination,
                                              long size, String password, byte[] metadata,
                                              int log2, int rounds, int keyId, byte[] salt,
                                              byte[] prefix) throws IOException {
        if (metadata != null && metadata.length > 0xFFFF - TAG_SIZE) {
            throw new FormatException("Metadata too long");
        }
        int metaSize = metadata == null ? 0 : metadata.length + TAG_SIZE;
        int flags = metadata == null ? 0 : 1;
        validateFields(flags, log2, rounds, metaSize, keyId, size);
        if (salt.length != 16 || prefix.length != 8) {
            throw new FormatException("Invalid salt or nonce prefix length");
        }
        byte[] aad = ByteBuffer.allocate(AAD_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .put(MAGIC).put((byte) VERSION).put((byte) flags).put((byte) log2).put((byte) 1)
            .putInt(rounds).putShort((short) metaSize).putShort((short) keyId)
            .put(salt).put(prefix).putLong(size).array();
        byte[] key = deriveKey(password, salt, rounds);
        destination.write(aad);
        destination.write(crypt(Cipher.ENCRYPT_MODE, key, nonce(prefix, HEADER_COUNTER),
                                aad, new byte[0]));
        if (metadata != null) {
            destination.write(crypt(Cipher.ENCRYPT_MODE, key, nonce(prefix, METADATA_COUNTER),
                                    null, metadata));
        }
        long remaining = size;
        long index = 0;
        while (remaining > 0) {
            int count = (int) Math.min(1 << log2, remaining);
            byte[] block = readExactly(source, count);
            destination.write(crypt(Cipher.ENCRYPT_MODE, key, nonce(prefix, index), aad, block));
            remaining -= count;
            index++;
        }
        if (source.read() != -1) throw new FormatException("Source exceeds plaintextSize");
    }

    private static byte[] readExactly(InputStream stream, int length) throws IOException {
        byte[] result = new byte[length];
        int received = 0;
        while (received < length) {
            int count = stream.read(result, received, length - received);
            if (count < 0) throw new FormatException("Truncated input");
            if (count == 0) {
                int one = stream.read();
                if (one < 0) throw new FormatException("Truncated input");
                result[received++] = (byte) one;
            } else {
                received += count;
            }
        }
        return result;
    }
}
