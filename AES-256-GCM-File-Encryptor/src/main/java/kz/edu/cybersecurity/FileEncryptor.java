
package kz.edu.cybersecurity;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;

public class FileEncryptor {

    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 12;
    private static final int ITERATIONS = 120000;
    private static final int TAG_SIZE = 128;
    private static final int BUFFER_SIZE = 64 * 1024;

    private static final byte[] MAGIC = {'A', 'G', 'C', 'M'};

    private final SecureRandom random = new SecureRandom();

    private SecretKey generateKey(char[] password, byte[] salt)
            throws Exception {

        PBEKeySpec spec = new PBEKeySpec(
                password, salt, ITERATIONS, KEY_SIZE
        );

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] key = factory.generateSecret(spec).getEncoded();

            return new SecretKeySpec(key, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    public void encrypt(Path input, Path output, char[] password)
            throws Exception {

        checkPaths(input, output);

        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];

        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey key = generateKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(TAG_SIZE, iv)
        );

        try (InputStream in = Files.newInputStream(input);
             OutputStream out = Files.newOutputStream(output)) {

            out.write(MAGIC);
            out.write(salt);
            out.write(iv);

            byte[] buffer = new byte[BUFFER_SIZE];
            int length;

            while ((length = in.read(buffer)) != -1) {
                byte[] encrypted = cipher.update(buffer, 0, length);

                if (encrypted != null) {
                    out.write(encrypted);
                }
            }

            byte[] finalData = cipher.doFinal();
            out.write(finalData);
        }
    }

    public void decrypt(Path input, Path output, char[] password)
            throws Exception {

        checkPaths(input, output);

        Path absoluteOutput = output.toAbsolutePath();
        Path parent = absoluteOutput.getParent();

        Path temp = Files.createTempFile(
                parent, "decrypt-", ".tmp"
        );

        boolean success = false;

        try (InputStream in = Files.newInputStream(input)) {

            byte[] magic = in.readNBytes(MAGIC.length);

            if (!java.util.Arrays.equals(magic, MAGIC)) {
                throw new IOException("Invalid encrypted file format");
            }

            byte[] salt = in.readNBytes(SALT_SIZE);
            byte[] iv = in.readNBytes(IV_SIZE);

            if (salt.length != SALT_SIZE || iv.length != IV_SIZE) {
                throw new IOException("Incomplete encrypted file");
            }

            SecretKey key = generateKey(password, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(TAG_SIZE, iv)
            );

            try (OutputStream out = Files.newOutputStream(temp)) {

                byte[] buffer = new byte[BUFFER_SIZE];
                int length;

                while ((length = in.read(buffer)) != -1) {
                    byte[] decrypted = cipher.update(buffer, 0, length);

                    if (decrypted != null) {
                        out.write(decrypted);
                    }
                }

                byte[] finalData = cipher.doFinal();
                out.write(finalData);
            }

            try {
                Files.move(temp, absoluteOutput,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, absoluteOutput,
                        StandardCopyOption.REPLACE_EXISTING);
            }

            success = true;

        } finally {
            if (!success) {
                Files.deleteIfExists(temp);
            }
        }
    }

    private void checkPaths(Path input, Path output)
            throws IOException {

        if (input == null || output == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }

        if (!Files.isRegularFile(input)) {
            throw new FileNotFoundException("Input file not found");
        }

        if (input.toAbsolutePath().normalize()
                .equals(output.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException(
                    "Input and output files must be different"
            );
        }
    }
}
