
package kz.edu.cybersecurity;

import java.nio.file.Path;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        FileEncryptor encryptor = new FileEncryptor();

        try {
            System.out.println("=== AES-256-GCM FILE ENCRYPTOR ===");
            System.out.println("1. Encrypt file");
            System.out.println("2. Decrypt file");
            System.out.print("Choose operation: ");

            String choice = scanner.nextLine();

            System.out.print("Input file path: ");
            Path input = Path.of(scanner.nextLine());

            System.out.print("Output file path: ");
            Path output = Path.of(scanner.nextLine());

            System.out.print("Enter password: ");
            char[] password = scanner.nextLine().toCharArray();

            if (password.length == 0) {
                throw new IllegalArgumentException(
                        "Password cannot be empty"
                );
            }

            if (choice.equals("1")) {
                encryptor.encrypt(input, output, password);
                System.out.println("File encrypted successfully!");
            } else if (choice.equals("2")) {
                encryptor.decrypt(input, output, password);
                System.out.println("File decrypted successfully!");
            } else {
                System.out.println("Invalid operation!");
            }

            java.util.Arrays.fill(password, '\0');

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
