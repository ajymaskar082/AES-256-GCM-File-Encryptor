
package kz.edu.cybersecurity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FileEncryptorTest {

    private final FileEncryptor encryptor = new FileEncryptor();

    private final char[] password = "StrongPassword123!".toCharArray();

    @Test
    void encryptAndDecryptSmallFile(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");
        Path decrypted = dir.resolve("decrypted.txt");

        Files.writeString(input, "Hello AES-256-GCM");

        encryptor.encrypt(input, encrypted, password);
        encryptor.decrypt(encrypted, decrypted, password);

        assertEquals(Files.readString(input), Files.readString(decrypted));
    }

    @Test
    void encryptAndDecryptEmptyFile(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("empty.txt");
        Path encrypted = dir.resolve("empty.enc");
        Path decrypted = dir.resolve("empty-out.txt");

        Files.createFile(input);

        encryptor.encrypt(input, encrypted, password);
        encryptor.decrypt(encrypted, decrypted, password);

        assertEquals(0, Files.size(decrypted));
    }

    @Test
    void encryptAndDecryptLargeFile(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("large.bin");
        Path encrypted = dir.resolve("large.enc");
        Path decrypted = dir.resolve("large-out.bin");

        byte[] data = new byte[1024 * 1024];
        new java.util.Random(42).nextBytes(data);
        Files.write(input, data);

        encryptor.encrypt(input, encrypted, password);
        encryptor.decrypt(encrypted, decrypted, password);

        assertArrayEquals(data, Files.readAllBytes(decrypted));
    }

    @Test
    void encryptedFileIsDifferentFromOriginal(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");

        Files.writeString(input, "Secret information");

        encryptor.encrypt(input, encrypted, password);

        assertFalse(java.util.Arrays.equals(
                Files.readAllBytes(input),
                Files.readAllBytes(encrypted)
        ));
    }

    @Test
    void encryptedFileIsCreated(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");

        Files.writeString(input, "Test");

        encryptor.encrypt(input, encrypted, password);

        assertTrue(Files.exists(encrypted));
    }

    @Test
    void wrongPasswordFailsDecryption(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");
        Path decrypted = dir.resolve("decrypted.txt");

        Files.writeString(input, "Secret");
        encryptor.encrypt(input, encrypted, password);

        assertThrows(Exception.class, () ->
                encryptor.decrypt(
                        encrypted,
                        decrypted,
                        "WrongPassword".toCharArray()
                )
        );

        assertFalse(Files.exists(decrypted));
    }

    @Test
    void corruptedEncryptedFileFails(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");
        Path decrypted = dir.resolve("decrypted.txt");

        Files.writeString(input, "Secret data");
        encryptor.encrypt(input, encrypted, password);

        byte[] data = Files.readAllBytes(encrypted);
        data[data.length - 1] ^= 1;
        Files.write(encrypted, data);

        assertThrows(Exception.class, () ->
                encryptor.decrypt(encrypted, decrypted, password)
        );
    }

    @Test
    void invalidFileFormatFails(@TempDir Path dir) throws Exception {
        Path invalid = dir.resolve("invalid.bin");
        Path output = dir.resolve("output.txt");

        Files.writeString(invalid, "Not an encrypted file");

        assertThrows(Exception.class, () ->
                encryptor.decrypt(invalid, output, password)
        );
    }

    @Test
    void missingInputFileFails(@TempDir Path dir) {
        Path missing = dir.resolve("missing.txt");
        Path output = dir.resolve("output.enc");

        assertThrows(Exception.class, () ->
                encryptor.encrypt(missing, output, password)
        );
    }

    @Test
    void nullInputPathFails() {
        assertThrows(Exception.class, () ->
                encryptor.encrypt(null, Path.of("output.enc"), password)
        );
    }

    @Test
    void nullOutputPathFails(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Files.writeString(input, "Test");

        assertThrows(Exception.class, () ->
                encryptor.encrypt(input, null, password)
        );
    }

    @Test
    void sameInputAndOutputPathFails(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("same.txt");
        Files.writeString(file, "Test");

        assertThrows(Exception.class, () ->
                encryptor.encrypt(file, file, password)
        );
    }

    @Test
    void eachEncryptionUsesDifferentSaltAndIv(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted1 = dir.resolve("first.enc");
        Path encrypted2 = dir.resolve("second.enc");

        Files.writeString(input, "Same content");

        encryptor.encrypt(input, encrypted1, password);
        encryptor.encrypt(input, encrypted2, password);

        byte[] first = Files.readAllBytes(encrypted1);
        byte[] second = Files.readAllBytes(encrypted2);

        assertFalse(java.util.Arrays.equals(
                java.util.Arrays.copyOfRange(first, 4, 32),
                java.util.Arrays.copyOfRange(second, 4, 32)
        ));
    }

    @Test
    void encryptedFileContainsCorrectHeader(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");

        Files.writeString(input, "Test");
        encryptor.encrypt(input, encrypted, password);

        byte[] header = Files.readAllBytes(encrypted);

        assertArrayEquals(
                new byte[]{'A', 'G', 'C', 'M'},
                java.util.Arrays.copyOfRange(header, 0, 4)
        );
    }

    @Test
    void decryptingDoesNotChangeEncryptedFile(@TempDir Path dir) throws Exception {
        Path input = dir.resolve("input.txt");
        Path encrypted = dir.resolve("encrypted.bin");
        Path decrypted = dir.resolve("decrypted.txt");

        Files.writeString(input, "Original content");
        encryptor.encrypt(input, encrypted, password);

        byte[] before = Files.readAllBytes(encrypted);

        encryptor.decrypt(encrypted, decrypted, password);

        byte[] after = Files.readAllBytes(encrypted);

        assertArrayEquals(before, after);
    }
}
