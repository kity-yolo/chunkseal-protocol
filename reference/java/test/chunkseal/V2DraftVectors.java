package chunkseal;

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 ChunkSeal contributors
// Additional GPLv3 permission: see ADDITIONAL-PERMISSION.md.

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Independent draft-vector calculations, not a public v2 container API. */
public final class V2DraftVectors {
    private static final byte[] LABEL = "ChunkSeal/v2/record-key\0".getBytes(StandardCharsets.US_ASCII);
    private static final long HEADER_COUNTER = 0xFFFFFFFFL;
    private static final long METADATA_COUNTER = 0xFFFFFFFEL;
    private static final HexFormat HEX = HexFormat.of();
    private static int assertions;

    private V2DraftVectors() {}

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        assertions++;
    }

    private static byte[] bytes(Properties vectors, String prefix, String field) {
        return HEX.parseHex(vectors.getProperty(prefix + field));
    }

    private static int number(Properties vectors, String prefix, String field) {
        return Integer.parseInt(vectors.getProperty(prefix + field));
    }

    private static byte[] concat(byte[]... parts) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part);
        return out.toByteArray();
    }

    private static byte[] counter(long value) {
        return ByteBuffer.allocate(4).putInt((int) value).array();
    }

    private static byte[] hmac(byte[] key, byte[] message) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.length == 0 ? new byte[] {0} : key, "HmacSHA256"));
        return mac.doFinal(message);
    }

    private static byte[] passwordMaterial(byte[] password, byte[] salt, int rounds)
            throws GeneralSecurityException, IOException {
        String text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(password)).toString();
        check(Arrays.equals(password, text.getBytes(StandardCharsets.UTF_8)), "strict UTF-8 password");
        byte[] block = hmac(password, concat(salt, counter(1)));
        byte[] result = block.clone();
        for (int iteration = 1; iteration < rounds; iteration++) {
            block = hmac(password, block);
            for (int index = 0; index < result.length; index++) result[index] ^= block[index];
        }
        return result;
    }

    private static byte[] aad(byte[] header, int kind, long index) throws IOException {
        return concat(header, new byte[] {(byte) kind}, counter(index));
    }

    private static byte[] key(byte[] header, byte[] prk, int kind, long index)
            throws GeneralSecurityException, IOException {
        return hmac(prk, concat(LABEL, aad(header, kind, index), new byte[] {1}));
    }

    private static byte[] nonce(byte[] header, long index) throws IOException {
        return concat(Arrays.copyOfRange(header, 32, 40), counter(index));
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] payload)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(payload);
    }

    private static byte[] sealRecord(Properties vectors, String prefix, String field,
                                     byte[] header, byte[] prk, int kind, long index, byte[] plain)
            throws GeneralSecurityException, IOException {
        byte[] recordKey = key(header, prk, kind, index);
        byte[] recordAad = aad(header, kind, index);
        byte[] recordNonce = nonce(header, index);
        check(Arrays.equals(recordKey, bytes(vectors, prefix, field + "_key_hex")), field + " key");
        check(Arrays.equals(recordAad, bytes(vectors, prefix, field + "_aad_hex")), field + " AAD");
        check(recordAad.length == 53, "AAD length");
        byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, recordKey, recordNonce, recordAad, plain);
        check(Arrays.equals(plain, crypt(Cipher.DECRYPT_MODE, recordKey, recordNonce, recordAad, ciphertext)),
              field + " round trip");
        byte[] damaged = ciphertext.clone();
        damaged[0] ^= 1;
        mustFail(recordKey, recordNonce, recordAad, damaged, field + " tamper");
        byte[] wrongAad = recordAad.clone();
        wrongAad[wrongAad.length - 1] ^= 1;
        mustFail(recordKey, recordNonce, wrongAad, ciphertext, field + " AAD binding");
        byte[] otherHeader = header.clone();
        otherHeader[14] ^= 1;
        mustFail(key(otherHeader, prk, kind, index), nonce(otherHeader, index),
                 aad(otherHeader, kind, index), ciphertext, field + " header binding");
        return ciphertext;
    }

    private static void mustFail(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, String label)
            throws GeneralSecurityException {
        try {
            crypt(Cipher.DECRYPT_MODE, key, nonce, aad, ciphertext);
        } catch (AEADBadTagException expected) {
            check(true, label);
            return;
        }
        throw new AssertionError(label);
    }

    private static void verifyRanges(byte[] header, byte[] prk, byte[] container, byte[] plain,
                                     int chunkSize, int metadataSize)
            throws GeneralSecurityException, IOException {
        int[][] ranges = {{0, plain.length}, {plain.length, 0}, {0, 0}, {4094, 12}, {8190, 9}};
        for (int[] range : ranges) {
            int start = range[0], length = range[1];
            if (start + length > plain.length) continue;
            ByteArrayOutputStream recovered = new ByteArrayOutputStream();
            if (length != 0) {
                int last = (start + length - 1) / chunkSize;
                for (int index = start / chunkSize; index <= last; index++) {
                    int size = Math.min(chunkSize, plain.length - index * chunkSize);
                    int offset = 64 + metadataSize + index * (chunkSize + 16);
                    byte[] record = Arrays.copyOfRange(container, offset, offset + size + 16);
                    byte[] block = crypt(Cipher.DECRYPT_MODE, key(header, prk, 2, index),
                                         nonce(header, index), aad(header, 2, index), record);
                    int base = index * chunkSize;
                    int firstByte = Math.max(0, start - base);
                    int endByte = Math.min(size, start + length - base);
                    recovered.write(block, firstByte, endByte - firstByte);
                }
            }
            check(Arrays.equals(recovered.toByteArray(), Arrays.copyOfRange(plain, start, start + length)),
                  "vector random range");
        }
    }

    private static void verify(Properties vectors, String name)
            throws GeneralSecurityException, IOException {
        String prefix = name + ".";
        int mode = number(vectors, prefix, "kdf_id");
        int rounds = number(vectors, prefix, "rounds");
        int log2 = number(vectors, prefix, "chunk_log2");
        int keyId = number(vectors, prefix, "key_id");
        byte[] salt = bytes(vectors, prefix, "salt_hex");
        byte[] noncePrefix = bytes(vectors, prefix, "nonce_prefix_hex");
        byte[] plain = bytes(vectors, prefix, "plaintext_hex");
        byte[] metadata = vectors.getProperty(prefix + "metadata_hex").equals("-")
            ? null : bytes(vectors, prefix, "metadata_hex");
        int metadataSize = metadata == null ? 0 : metadata.length + 16;
        byte[] header = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN)
            .put("CSEA".getBytes(StandardCharsets.US_ASCII)).put((byte) 2)
            .put((byte) (metadata == null ? 0 : 1)).put((byte) log2).put((byte) mode)
            .putInt(rounds).putShort((short) metadataSize).putShort((short) keyId)
            .put(salt).put(noncePrefix).putLong(plain.length).array();
        byte[] ikm;
        if (mode == 2) {
            check(rounds == 0, "raw rounds zero");
            ikm = bytes(vectors, prefix, "master_key_hex");
            check(ikm.length == 16 || ikm.length == 32, "raw key length");
        } else {
            check(mode == 1 && rounds > 0, "explicit password mode");
            ikm = passwordMaterial(bytes(vectors, prefix, "password_utf8_hex"), salt, rounds);
        }
        check(Arrays.equals(ikm, bytes(vectors, prefix, "ikm_hex")), "IKM");
        byte[] prk = hmac(salt, ikm);
        check(Arrays.equals(prk, bytes(vectors, prefix, "prk_hex")), "PRK");
        byte[] headerTag = sealRecord(vectors, prefix, "header", header, prk, 0, HEADER_COUNTER, new byte[0]);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(header);
        output.write(headerTag);
        check(Arrays.equals(output.toByteArray(), bytes(vectors, prefix, "header_hex")), "complete header");
        if (metadata != null) {
            output.write(sealRecord(vectors, prefix, "metadata", header, prk, 1, METADATA_COUNTER, metadata));
        } else {
            check(vectors.getProperty(prefix + "metadata_key_hex").equals("-"), "absent metadata key");
            check(vectors.getProperty(prefix + "metadata_aad_hex").equals("-"), "absent metadata AAD");
        }
        int chunkSize = 1 << log2;
        int count = (plain.length + chunkSize - 1) / chunkSize;
        check(count == number(vectors, prefix, "data_record_count"), "data record count");
        for (int index = 0; index < count; index++) {
            check(output.size() == 64 + metadataSize + index * (chunkSize + 16), "data offset");
            byte[] block = Arrays.copyOfRange(plain, index * chunkSize, Math.min(plain.length, (index + 1) * chunkSize));
            output.write(sealRecord(vectors, prefix, "data_" + index, header, prk, 2, index, block));
        }
        byte[] container = output.toByteArray();
        check(container.length == 64 + metadataSize + plain.length + count * 16, "exact container size");
        check(Arrays.equals(container, bytes(vectors, prefix, "container_hex")), "Python/Java exact ciphertext");
        byte[] wrongMaterial = ikm.clone();
        wrongMaterial[0] ^= 1;
        byte[] wrongPrk = hmac(salt, wrongMaterial);
        mustFail(key(header, wrongPrk, 0, HEADER_COUNTER), nonce(header, HEADER_COUNTER),
                 aad(header, 0, HEADER_COUNTER), headerTag, "wrong secret");
        if (count >= 2) {
            int offset = 64 + metadataSize;
            byte[] first = Arrays.copyOfRange(container, offset, offset + chunkSize + 16);
            mustFail(key(header, prk, 2, 1), nonce(header, 1), aad(header, 2, 1), first, "data reordering");
        }
        verifyRanges(header, prk, container, plain, chunkSize, metadataSize);
        try {
            new ChunkSeal.Reader(ChunkSeal.bytesSource(container), "v2-must-not-be-read-as-v1");
        } catch (ChunkSeal.FormatException expected) {
            check(true, "current v1 reader rejects v2");
            return;
        }
        throw new AssertionError("current v1 reader accepted v2");
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        if (args.length != 1) throw new IllegalArgumentException("Expected v2.properties path");
        Properties vectors = new Properties();
        try (InputStream source = Files.newInputStream(Path.of(args[0]))) {
            vectors.load(source);
        }
        String[] names = vectors.getProperty("vectors").split(",");
        for (String name : names) verify(vectors, name);
        System.out.println("Java v2 draft vectors: " + names.length + " vectors, " + assertions + " assertions passed");
    }
}
