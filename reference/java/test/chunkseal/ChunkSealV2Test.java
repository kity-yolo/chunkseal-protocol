package chunkseal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;
import java.util.Random;

/** Dependency-free v2 known-answer, mutation, boundary, and interoperability checks. */
public final class ChunkSealV2Test {
    private static int assertions;
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] KEY = key(32, 0x20);

    @FunctionalInterface private interface Operation { void run() throws IOException; }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static void equal(byte[] expected, byte[] actual, String message) {
        check(Arrays.equals(expected, actual), message);
    }

    private static void fails(Class<? extends IOException> type, Operation operation)
            throws IOException {
        try {
            operation.run();
        } catch (IOException error) {
            check(type.isInstance(error), "Unexpected exception: " + error);
            return;
        }
        throw new AssertionError("Expected " + type.getSimpleName());
    }

    private static byte[] key(int length, int start) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) result[index] = (byte) (start + index);
        return result;
    }

    private static byte[] payload(int size, int multiplier, int addend) {
        byte[] result = new byte[size];
        for (int index = 0; index < size; index++) result[index] = (byte) (index * multiplier + addend);
        return result;
    }

    private static void knownAnswers(Path path) throws IOException {
        Properties fixtures = new Properties();
        try (InputStream input = Files.newInputStream(path)) { fixtures.load(input); }
        for (String name : fixtures.getProperty("vectors").split(",")) {
            String prefix = name + ".";
            byte[] plain = HEX.parseHex(fixtures.getProperty(prefix + "plaintext_hex"));
            String encodedMeta = fixtures.getProperty(prefix + "metadata_hex");
            byte[] metadata = encodedMeta.equals("-") ? null : HEX.parseHex(encodedMeta);
            byte[] salt = HEX.parseHex(fixtures.getProperty(prefix + "salt_hex"));
            byte[] noncePrefix = HEX.parseHex(fixtures.getProperty(prefix + "nonce_prefix_hex"));
            int log2 = Integer.parseInt(fixtures.getProperty(prefix + "chunk_log2"));
            int keyId = Integer.parseInt(fixtures.getProperty(prefix + "key_id"));
            int kdfId = Integer.parseInt(fixtures.getProperty(prefix + "kdf_id"));
            byte[] expected = HEX.parseHex(fixtures.getProperty(prefix + "container_hex"));
            byte[] actual;
            ChunkSealV2.Reader reader;
            if (kdfId == 2) {
                byte[] masterKey = HEX.parseHex(fixtures.getProperty(prefix + "master_key_hex"));
                actual = ChunkSealV2.encryptDeterministic(plain, masterKey, metadata, log2,
                                                          keyId, salt, noncePrefix);
                reader = new ChunkSealV2.Reader(ChunkSeal.bytesSource(expected), masterKey);
            } else {
                String password = new String(
                    HEX.parseHex(fixtures.getProperty(prefix + "password_utf8_hex")),
                    StandardCharsets.UTF_8);
                int rounds = Integer.parseInt(fixtures.getProperty(prefix + "rounds"));
                actual = ChunkSealV2.encryptDeterministic(plain, password, metadata, log2,
                                                          rounds, keyId, salt, noncePrefix);
                reader = new ChunkSealV2.Reader(ChunkSeal.bytesSource(expected), password);
            }
            equal(expected, actual, name + " complete ciphertext");
            equal(HEX.parseHex(fixtures.getProperty(prefix + "header_hex")),
                  Arrays.copyOf(expected, 64), name + " complete header");
            equal(plain, reader.read(0, plain.length), name + " plaintext");
            equal(metadata, reader.metadata(), name + " metadata");
            check(reader.header().keyId == keyId, name + " key identifier");
            check(reader.header().kdfId == kdfId, name + " KDF identifier");
        }
    }

    private static byte[] header(long size, int kdfId, int rounds) {
        byte[] bytes = new byte[64];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            .put("CSEA".getBytes(StandardCharsets.US_ASCII)).put((byte) 2)
            .put((byte) 0).put((byte) 12).put((byte) kdfId).putInt(rounds)
            .putShort((short) 0).putShort((short) 0);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putLong(40, size);
        return bytes;
    }

    private static void behaviorChecks() throws IOException {
        byte[] plain = payload(3 * 4096 + 31, 37, 19);
        byte[] cipher = ChunkSealV2.encrypt(plain, KEY, new byte[] {0, (byte) 255}, 12, 7);
        ChunkSealV2.Reader reader = new ChunkSealV2.Reader(ChunkSeal.bytesSource(cipher), KEY);
        Random random = new Random(42);
        for (int index = 0; index < 150; index++) {
            int offset = random.nextInt(plain.length + 1);
            int count = random.nextInt(plain.length - offset + 1);
            equal(Arrays.copyOfRange(plain, offset, offset + count),
                  reader.read(offset, count), "random range");
        }
        equal(Arrays.copyOfRange(plain, 4090, 4110), reader.read(4090, 20), "cross-boundary range");
        equal(new byte[0], reader.read(plain.length, 0), "empty EOF read");
        fails(ChunkSeal.FormatException.class, () -> reader.read(Long.MAX_VALUE, 1));
        fails(ChunkSeal.FormatException.class, () -> reader.read(-1, 1));
        fails(ChunkSeal.FormatException.class, () -> reader.read(plain.length, 1));
        fails(ChunkSeal.AuthenticationException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(cipher), key(32, 0)));

        byte[] changedHeader = cipher.clone();
        changedHeader[14] ^= 1;
        fails(ChunkSeal.AuthenticationException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(changedHeader), KEY));

        byte[] changedMeta = cipher.clone();
        changedMeta[64] ^= 1;
        ChunkSealV2.Reader badMeta = new ChunkSealV2.Reader(ChunkSeal.bytesSource(changedMeta), KEY);
        fails(ChunkSeal.AuthenticationException.class, badMeta::metadata);

        byte[] changedData = cipher.clone();
        changedData[(int) reader.header().chunkOffset(0)] ^= 1;
        ChunkSealV2.Reader badData = new ChunkSealV2.Reader(ChunkSeal.bytesSource(changedData), KEY);
        fails(ChunkSeal.AuthenticationException.class, () -> badData.readChunk(0));

        byte[] unread = cipher.clone();
        unread[(int) reader.header().chunkOffset(2)] ^= 1;
        ChunkSealV2.Reader partial = new ChunkSealV2.Reader(ChunkSeal.bytesSource(unread), KEY);
        equal(Arrays.copyOf(plain, 20), partial.read(0, 20), "unread record not required");
        fails(ChunkSeal.AuthenticationException.class,
              () -> partial.decryptTo(new ByteArrayOutputStream()));

        byte[] swapped = cipher.clone();
        int start = (int) reader.header().chunkOffset(0);
        System.arraycopy(cipher, start + 4112, swapped, start, 4112);
        System.arraycopy(cipher, start, swapped, start + 4112, 4112);
        ChunkSealV2.Reader badOrder = new ChunkSealV2.Reader(ChunkSeal.bytesSource(swapped), KEY);
        fails(ChunkSeal.AuthenticationException.class, () -> badOrder.readChunk(0));

        byte[] other = ChunkSealV2.encrypt(plain, KEY, null, 12, 7);
        byte[] substituted = cipher.clone();
        System.arraycopy(other, 64, substituted, 64, 4112);
        fails(ChunkSeal.AuthenticationException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(substituted), KEY).readChunk(0));

        fails(ChunkSeal.FormatException.class, () -> new ChunkSealV2.Reader(
            ChunkSeal.bytesSource(Arrays.copyOf(cipher, cipher.length - 1)), KEY));
        fails(ChunkSeal.FormatException.class, () -> new ChunkSealV2.Reader(
            ChunkSeal.bytesSource(Arrays.copyOf(cipher, cipher.length + 1)), KEY));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSealV2.parseHeader(Arrays.copyOf(cipher, 63)));

        byte[][] malformed = {
            header(0, 0, 0), header(0, 3, 0), header(0, 2, 1),
            header(0, 1, 0), header(-1, 2, 0),
        };
        for (byte[] bytes : malformed) {
            fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.parseHeader(bytes));
        }
        byte[] badVersion = header(0, 2, 0);
        badVersion[4] = 3;
        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.parseHeader(badVersion));
        byte[] badFlags = header(0, 2, 0);
        badFlags[5] = 2;
        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.parseHeader(badFlags));
        for (int log2 : new int[] {11, 27}) {
            byte[] badLog2 = header(0, 2, 0);
            badLog2[6] = (byte) log2;
            fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.parseHeader(badLog2));
        }
        byte[] badMetaSize = header(0, 2, 0);
        ByteBuffer.wrap(badMetaSize).order(ByteOrder.LITTLE_ENDIAN).putShort(12, (short) 16);
        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.parseHeader(badMetaSize));
        byte[] negativeRounds = header(0, 1, 0x80000000);
        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.parseHeader(negativeRounds));

        byte[] excessiveRounds = header(0, 1, 6_000_000);
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(excessiveRounds), "password"));
        byte[] limited = ChunkSealV2.encrypt(new byte[] {120}, "password", null, 12, 3000, 0);
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(limited), "password", 2000));
        equal(new byte[] {120},
              new ChunkSealV2.Reader(ChunkSeal.bytesSource(limited), "password", 4000).read(0, 1),
              "raised rounds policy");

        fails(ChunkSeal.FormatException.class,
              () -> ChunkSealV2.encrypt(new byte[0], KEY, null, 11, 0));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSealV2.encrypt(new byte[0], "password", null, 12, 0, 0));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSealV2.encrypt(new byte[0], KEY, new byte[65520], 12, 0));
        for (int length : new int[] {0, 15, 17, 31, 33, 64}) {
            fails(ChunkSeal.FormatException.class,
                  () -> ChunkSealV2.encrypt(new byte[0], key(length, 0), null, 12, 0));
        }
        for (int length : new int[] {16, 32}) {
            byte[] sized = ChunkSealV2.encrypt(new byte[] {120}, key(length, 0), null, 12, 0);
            equal(new byte[] {120},
                  new ChunkSealV2.Reader(ChunkSeal.bytesSource(sized), key(length, 0)).read(0, 1),
                  "master key length " + length);
        }

        byte[] maximumMeta = ChunkSealV2.encrypt(new byte[0], KEY, new byte[65519], 12, 0);
        check(new ChunkSealV2.Reader(ChunkSeal.bytesSource(maximumMeta), KEY)
              .metadata().length == 65519, "maximum metadata length");
        byte[] emptyMeta = ChunkSealV2.encrypt(new byte[0], KEY, new byte[0], 12, 0);
        equal(new byte[0], new ChunkSealV2.Reader(ChunkSeal.bytesSource(emptyMeta), KEY).metadata(),
              "present empty metadata");
        byte[] absentMeta = ChunkSealV2.encrypt(new byte[0], KEY, null, 12, 0);
        check(new ChunkSealV2.Reader(ChunkSeal.bytesSource(absentMeta), KEY).metadata() == null,
              "absent metadata");
        check(absentMeta.length == 64, "empty absent-metadata container size");

        ChunkSealV2.Header large = ChunkSealV2.parseHeader(header((1L << 33) + 12345, 2, 0));
        check(large.chunkOffset(1L << 21) > Integer.MAX_VALUE, "64-bit record offset");
        long maximumSize = ChunkSeal.MAX_CHUNKS * 4096;
        ChunkSealV2.Header maximum = ChunkSealV2.parseHeader(header(maximumSize, 2, 0));
        check(maximum.chunkCount() == ChunkSeal.MAX_CHUNKS, "last available data nonce");
        maximum.chunkOffset(ChunkSeal.MAX_CHUNKS - 1);
        fails(ChunkSeal.FormatException.class, () -> maximum.chunkOffset(ChunkSeal.MAX_CHUNKS));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSealV2.parseHeader(header(maximumSize + 1, 2, 0)));

        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.encrypt(
            new byte[0], String.valueOf((char) 0xD800), null, 12, 1000, 0));
        byte[] composed = ChunkSealV2.encrypt(new byte[] {120}, "é", null, 12, 1000, 0);
        byte[] decomposed = ChunkSealV2.encrypt(new byte[] {120}, "e\u0301", null, 12, 1000, 0);
        check(!Arrays.equals(Arrays.copyOfRange(composed, 64, composed.length),
              Arrays.copyOfRange(decomposed, 64, decomposed.length)),
              "no implicit Unicode normalization");
        byte[] nulPassword = ChunkSealV2.encrypt(new byte[] {120}, "a\0b", null, 12, 1000, 0);
        equal(new byte[] {120},
              new ChunkSealV2.Reader(ChunkSeal.bytesSource(nulPassword), "a\0b").read(0, 1),
              "embedded NUL password");

        byte[] passwordCipher = ChunkSealV2.encrypt(plain, "test-password", null, 12, 1000, 7);
        equal(plain, new ChunkSealV2.Reader(ChunkSeal.bytesSource(passwordCipher), "test-password")
              .read(0, plain.length), "password mode round trip");
        fails(ChunkSeal.AuthenticationException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(passwordCipher), "wrong"));
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(cipher), "test-password"));
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(passwordCipher), KEY));

        byte[] v1 = ChunkSeal.encrypt(plain, "test-password", null, 12, 1000, 7);
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSeal.Reader(ChunkSeal.bytesSource(cipher), "test-password"));
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(v1), "test-password"));
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSealV2.Reader(ChunkSeal.bytesSource(v1), KEY));

        byte[] first = ChunkSealV2.encrypt(new byte[] {120}, KEY, null, 20, 0);
        byte[] second = ChunkSealV2.encrypt(new byte[] {120}, KEY, null, 20, 0);
        check(!Arrays.equals(Arrays.copyOfRange(first, 16, 32),
              Arrays.copyOfRange(second, 16, 32)), "fresh salt");
        check(!Arrays.equals(Arrays.copyOfRange(first, 32, 40),
              Arrays.copyOfRange(second, 32, 40)), "fresh nonce prefix");
        ChunkSealV2.Header defaults = ChunkSealV2.parseHeader(Arrays.copyOf(first, 64));
        check(defaults.kdfId == 2 && defaults.rounds == 0, "raw mode header fields");

        InputStream slow = new ByteArrayInputStream(plain) {
            @Override public synchronized int read(byte[] buffer, int offset, int length) {
                return super.read(buffer, offset, Math.min(length, 37));
            }
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ChunkSealV2.encrypt(slow, output, plain.length, KEY, null, 12, 0);
        equal(plain, new ChunkSealV2.Reader(ChunkSeal.bytesSource(output.toByteArray()), KEY)
              .read(0, plain.length), "short streaming input reads");
        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.encrypt(
            new ByteArrayInputStream(new byte[1]), new ByteArrayOutputStream(), 2, KEY, null, 12, 0));
        fails(ChunkSeal.FormatException.class, () -> ChunkSealV2.encrypt(
            new ByteArrayInputStream(new byte[1]), new ByteArrayOutputStream(), 0, KEY, null, 12, 0));
    }

    private static void interoperability(Path directory) throws IOException {
        String password = "interop🔒-v2-password";
        byte[] plain = payload(8191 + 17, 53, 7);
        byte[] metadata = "{\"name\":\"interop-v2.bin\"}".getBytes(StandardCharsets.UTF_8);
        ChunkSealV2.Reader rawReader = new ChunkSealV2.Reader(
            ChunkSeal.bytesSource(Files.readAllBytes(directory.resolve("python-v2-raw.cseal"))), KEY);
        equal(plain, rawReader.read(0, plain.length), "independent Python raw-key ciphertext");
        equal(metadata, rawReader.metadata(), "independent Python raw-key metadata");
        check(rawReader.header().keyId == 42, "independent Python raw-key key identifier");
        ChunkSealV2.Reader passwordReader = new ChunkSealV2.Reader(
            ChunkSeal.bytesSource(Files.readAllBytes(directory.resolve("python-v2-pass.cseal"))),
            password);
        equal(plain, passwordReader.read(0, plain.length), "independent Python password ciphertext");
        equal(metadata, passwordReader.metadata(), "independent Python password metadata");
        Files.write(directory.resolve("java-v2-raw.cseal"),
                    ChunkSealV2.encrypt(plain, KEY, metadata, 12, 42));
        Files.write(directory.resolve("java-v2-pass.cseal"),
                    ChunkSealV2.encrypt(plain, password, metadata, 12, 1000, 42));
        System.out.println("Java verified the independently written Python v2 containers.");
    }

    public static void main(String[] arguments) throws IOException {
        knownAnswers(Path.of(arguments[0]));
        behaviorChecks();
        interoperability(Path.of(arguments[1]));
        System.out.println("Java v2 protocol checks passed (" + assertions + " assertions).");
    }
}