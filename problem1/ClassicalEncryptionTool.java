import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

/**
 * Classical Encryption Tool - Main Driver
 * 
 * Supports:
 *   1. Monoalphabetic Substitution Cipher
 *   2. Polyalphabetic Cipher (Vigenère)
 *   3. Transposition Cipher (Columnar)
 * 
 * The user chooses the cipher type, mode (encrypt/decrypt),
 * input file, output file, and key.
 */
public class ClassicalEncryptionTool {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("==============================================");
        System.out.println("       Classical Encryption Tool");
        System.out.println("==============================================");
        System.out.println();

        // 1. Choose cipher type
        System.out.println("Select cipher type:");
        System.out.println("  1. Monoalphabetic Substitution Cipher");
        System.out.println("  2. Polyalphabetic Cipher (Vigenere)");
        System.out.println("  3. Transposition Cipher");
        System.out.print("Choice (1/2/3): ");
        int cipherChoice = Integer.parseInt(scanner.nextLine().trim());

        // 2. Choose mode
        System.out.println();
        System.out.println("Select mode:");
        System.out.println("  1. Encrypt");
        System.out.println("  2. Decrypt");
        System.out.print("Choice (1/2): ");
        int modeChoice = Integer.parseInt(scanner.nextLine().trim());
        boolean encrypt = (modeChoice == 1);

        // 3. Input file path
        System.out.println();
        System.out.print("Enter input file path: ");
        String inputPath = scanner.nextLine().trim();

        // 4. Output file path
        System.out.print("Enter output file path: ");
        String outputPath = scanner.nextLine().trim();

        // 5. Read input file
        String inputText;
        try {
            inputText = new String(Files.readAllBytes(Paths.get(inputPath)));
        } catch (IOException e) {
            System.err.println("Error reading input file: " + e.getMessage());
            return;
        }

        // 6. Get key and process
        String result;
        try {
            switch (cipherChoice) {
                case 1:
                    result = handleMonoalphabetic(scanner, inputText, encrypt);
                    break;
                case 2:
                    result = handlePolyalphabetic(scanner, inputText, encrypt);
                    break;
                case 3:
                    result = handleTransposition(scanner, inputText, encrypt);
                    break;
                default:
                    System.err.println("Invalid cipher choice.");
                    return;
            }
        } catch (Exception e) {
            System.err.println("Error during processing: " + e.getMessage());
            return;
        }

        // 7. Write output file
        try {
            Files.write(Paths.get(outputPath), result.getBytes());
            System.out.println();
            System.out.println("==============================================");
            System.out.println((encrypt ? "Encryption" : "Decryption") + " completed successfully!");
            System.out.println("Output written to: " + outputPath);
            System.out.println("==============================================");
        } catch (IOException e) {
            System.err.println("Error writing output file: " + e.getMessage());
        }
    }

    /**
     * Handle Monoalphabetic cipher interaction.
     */
    private static String handleMonoalphabetic(Scanner scanner, String text, boolean encrypt) {
        System.out.println();
        System.out.println("--- Monoalphabetic Substitution Cipher ---");
        System.out.println("Enter the substitution key (26 unique letters, e.g., QWERTYUIOPASDFGHJKLZXCVBNM):");
        System.out.print("Key: ");
        String key = scanner.nextLine().trim();

        MonoalphabeticCipher cipher = new MonoalphabeticCipher(key);

        System.out.println();
        System.out.println("Substitution Table:");
        System.out.print("  Plain:  ");
        for (char c = 'A'; c <= 'Z'; c++) System.out.print(c + " ");
        System.out.println();
        System.out.print("  Cipher: ");
        for (char c : cipher.getKey().toCharArray()) System.out.print(c + " ");
        System.out.println();

        if (encrypt) {
            return cipher.encrypt(text);
        } else {
            return cipher.decrypt(text);
        }
    }

    /**
     * Handle Polyalphabetic (Vigenère) cipher interaction.
     */
    private static String handlePolyalphabetic(Scanner scanner, String text, boolean encrypt) {
        System.out.println();
        System.out.println("--- Polyalphabetic Cipher (Vigenere) ---");
        System.out.println("Enter the keyword (e.g., SECRET):");
        System.out.print("Keyword: ");
        String keyword = scanner.nextLine().trim();

        PolyalphabeticCipher cipher = new PolyalphabeticCipher(keyword);

        System.out.println("Using keyword: " + cipher.getKeyword());

        if (encrypt) {
            return cipher.encrypt(text);
        } else {
            return cipher.decrypt(text);
        }
    }

    /**
     * Handle Transposition cipher interaction.
     */
    private static String handleTransposition(Scanner scanner, String text, boolean encrypt) {
        System.out.println();
        System.out.println("--- Transposition Cipher ---");
        System.out.println("Enter the permutation key (space-separated numbers, e.g., 3 1 4 2):");
        System.out.print("Key: ");
        String keyStr = scanner.nextLine().trim();

        TranspositionCipher cipher = new TranspositionCipher(keyStr);

        System.out.print("Permutation order: ");
        for (int k : cipher.getKey()) System.out.print(k + " ");
        System.out.println();

        if (encrypt) {
            return cipher.encrypt(text);
        } else {
            return cipher.decrypt(text);
        }
    }
}
