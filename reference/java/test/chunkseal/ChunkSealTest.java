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

/** Dependency-free known-answer, mutation, boundary, and interoperability checks. */
public final class ChunkSealTest {
    private static int assertions;
    private static final HexFormat HEX = HexFormat.of();

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
            String password = new String(HEX.parseHex(fixtures.getProperty(prefix + "password_utf8_hex")),
                                         StandardCharsets.UTF_8);
            byte[] plain = HEX.parseHex(fixtures.getProperty(prefix + "plaintext_hex"));
            String encodedMeta = fixtures.getProperty(prefix + "metadata_hex");
            byte[] metadata = encodedMeta.equals("-") ? null : HEX.parseHex(encodedMeta);
            byte[] salt = HEX.parseHex(fixtures.getProperty(prefix + "salt_hex"));
            byte[] noncePrefix = HEX.parseHex(fixtures.getProperty(prefix + "nonce_prefix_hex"));
            int rounds = Integer.parseInt(fixtures.getProperty(prefix + "rounds"));
            int log2 = Integer.parseInt(fixtures.getProperty(prefix + "chunk_log2"));
            int keyId = Integer.parseInt(fixtures.getProperty(prefix + "key_id"));
            byte[] expected = HEX.parseHex(fixtures.getProperty(prefix + "container_hex"));
            equal(HEX.parseHex(fixtures.getProperty(prefix + "key_hex")),
                  ChunkSeal.deriveKey(password, salt, rounds), name + " derived key");
            equal(expected, ChunkSeal.encryptDeterministic(plain, password, metadata, log2,
                  rounds, keyId, salt, noncePrefix), name + " complete ciphertext");
            equal(HEX.parseHex(fixtures.getProperty(prefix + "header_hex")),
                  Arrays.copyOf(expected, 64), name + " complete header");
            ChunkSeal.Reader reader = new ChunkSeal.Reader(ChunkSeal.bytesSource(expected), password);
            equal(plain, reader.read(0, plain.length), name + " plaintext");
            equal(metadata, reader.metadata(), name + " metadata");
            check(reader.header().keyId == keyId, name + " key identifier");
        }
    }

    private static byte[] header(long size) {
        byte[] bytes = new byte[64];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            .put("CSEA".getBytes(StandardCharsets.US_ASCII)).put((byte) 1)
            .put((byte) 0).put((byte) 12).put((byte) 1).putInt(1000)
            .putShort((short) 0).putShort((short) 0);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putLong(40, size);
        return bytes;
    }

    private static void behaviorChecks() throws IOException {
        byte[] plain = payload(3 * 4096 + 31, 37, 19);
        String password = "test-password";
        byte[] cipher = ChunkSeal.encrypt(plain, password, new byte[] {0, (byte) 255}, 12, 1000, 7);
        ChunkSeal.Reader reader = new ChunkSeal.Reader(ChunkSeal.bytesSource(cipher), password);
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
              () -> new ChunkSeal.Reader(ChunkSeal.bytesSource(cipher), "wrong"));

        byte[] changedHeader = cipher.clone();
        changedHeader[14] ^= 1;
        fails(ChunkSeal.AuthenticationException.class,
              () -> new ChunkSeal.Reader(ChunkSeal.bytesSource(changedHeader), password));

        byte[] changedMeta = cipher.clone();
        changedMeta[64] ^= 1;
        ChunkSeal.Reader badMeta = new ChunkSeal.Reader(ChunkSeal.bytesSource(changedMeta), password);
        fails(ChunkSeal.AuthenticationException.class, badMeta::metadata);

        byte[] changedData = cipher.clone();
        changedData[(int) reader.header().chunkOffset(0)] ^= 1;
        ChunkSeal.Reader badData = new ChunkSeal.Reader(ChunkSeal.bytesSource(changedData), password);
        fails(ChunkSeal.AuthenticationException.class, () -> badData.readChunk(0));

        byte[] swapped = cipher.clone();
        int start = (int) reader.header().chunkOffset(0);
        System.arraycopy(cipher, start + 4112, swapped, start, 4112);
        System.arraycopy(cipher, start, swapped, start + 4112, 4112);
        ChunkSeal.Reader badOrder = new ChunkSeal.Reader(ChunkSeal.bytesSource(swapped), password);
        fails(ChunkSeal.AuthenticationException.class, () -> badOrder.readChunk(0));

        fails(ChunkSeal.FormatException.class, () -> new ChunkSeal.Reader(
            ChunkSeal.bytesSource(Arrays.copyOf(cipher, cipher.length - 1)), password));
        fails(ChunkSeal.FormatException.class, () -> new ChunkSeal.Reader(
            ChunkSeal.bytesSource(Arrays.copyOf(cipher, cipher.length + 1)), password));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSeal.parseHeader(Arrays.copyOf(cipher, 63)));

        byte[] excessiveRounds = header(0);
        ByteBuffer.wrap(excessiveRounds).order(ByteOrder.LITTLE_ENDIAN).putInt(8, 6_000_000);
        fails(ChunkSeal.FormatException.class,
              () -> new ChunkSeal.Reader(ChunkSeal.bytesSource(excessiveRounds), password));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSeal.encrypt(new byte[0], password, null, 11, 1000, 0));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSeal.encrypt(new byte[0], password, null, 12, 0, 0));
        fails(ChunkSeal.FormatException.class,
              () -> ChunkSeal.encrypt(new byte[0], password, new byte[65520], 12, 1000, 0));

        byte[] maximumMeta = ChunkSeal.encrypt(new byte[0], password, new byte[65519], 12, 1000, 0);
        check(new ChunkSeal.Reader(ChunkSeal.bytesSource(maximumMeta), password)
              .metadata().length == 65519, "maximum metadata length");
        byte[] emptyMeta = ChunkSeal.encrypt(new byte[0], password, new byte[0], 12, 1000, 0);
        equal(new byte[0], new ChunkSeal.Reader(ChunkSeal.bytesSource(emptyMeta), password).metadata(),
              "present empty metadata");

        ChunkSeal.Header large = ChunkSeal.parseHeader(header((1L << 33) + 12345));
        check(large.chunkOffset(1L << 21) > Integer.MAX_VALUE, "64-bit record offset");
        long maximumSize = ChunkSeal.MAX_CHUNKS * 4096;
        ChunkSeal.Header maximum = ChunkSeal.parseHeader(header(maximumSize));
        check(maximum.chunkCount() == ChunkSeal.MAX_CHUNKS, "last available data nonce");
        maximum.chunkOffset(ChunkSeal.MAX_CHUNKS - 1);
        fails(ChunkSeal.FormatException.class, () -> maximum.chunkOffset(ChunkSeal.MAX_CHUNKS));
        fails(ChunkSeal.FormatException.class, () -> ChunkSeal.parseHeader(header(maximumSize + 1)));

        fails(ChunkSeal.FormatException.class,
              () -> ChunkSeal.deriveKey(String.valueOf((char) 0xD800), new byte[16], 1000));
        check(!Arrays.equals(ChunkSeal.deriveKey("é", new byte[16], 1000),
              ChunkSeal.deriveKey("é", new byte[16], 1000)), "no implicit Unicode normalization");

        InputStream slow = new ByteArrayInputStream(plain) {
            @Override public synchronized int read(byte[] buffer, int offset, int length) {
                return super.read(buffer, offset, Math.min(length, 37));
            }
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ChunkSeal.encrypt(slow, output, plain.length, password, null, 12, 1000, 0);
        equal(plain, new ChunkSeal.Reader(ChunkSeal.bytesSource(output.toByteArray()), password)
              .read(0, plain.length), "short streaming input reads");
        fails(ChunkSeal.FormatException.class, () -> ChunkSeal.encrypt(
            new ByteArrayInputStream(new byte[1]), new ByteArrayOutputStream(), 2,
            password, null, 12, 1000, 0));
        fails(ChunkSeal.FormatException.class, () -> ChunkSeal.encrypt(
            new ByteArrayInputStream(new byte[1]), new ByteArrayOutputStream(), 0,
            password, null, 12, 1000, 0));
    }

    private static void interoperability(Path directory) throws IOException {
        String password = "interop🔒-password";
        byte[] plain = payload(8191 + 17, 53, 7);
        byte[] metadata = "{\"name\":\"interop.bin\"}".getBytes(StandardCharsets.UTF_8);
        ChunkSeal.Reader reader = new ChunkSeal.Reader(
            ChunkSeal.bytesSource(Files.readAllBytes(directory.resolve("python.cseal"))), password);
        equal(plain, reader.read(0, plain.length), "independent Python ciphertext");
        equal(metadata, reader.metadata(), "independent Python metadata");
        check(reader.header().keyId == 42, "independent Python key identifier");
        Files.write(directory.resolve("java.cseal"),
                    ChunkSeal.encrypt(plain, password, metadata, 12, 1000, 42));
        System.out.println("Java verified the independently written Python container.");
    }

    public static void main(String[] arguments) throws IOException {
        knownAnswers(Path.of(arguments[0]));
        behaviorChecks();
        interoperability(Path.of(arguments[1]));
        System.out.println("Java protocol checks passed (" + assertions + " assertions).");
    }
}
