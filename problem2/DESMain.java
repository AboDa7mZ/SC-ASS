import java.util.Scanner;

/**
 * DES Encryption Tool - Main Driver
 * 
 * Takes a 64-bit key and a 64-bit plaintext block (in hexadecimal),
 * applies DES encryption, and shows all intermediate steps.
 * Also supports decryption to verify correctness.
 */
public class DESMain {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("==============================================");
        System.out.println("         DES Encryption Tool");
        System.out.println("==============================================");
        System.out.println();

        // Mode selection
        System.out.println("Select mode:");
        System.out.println("  1. Encrypt");
        System.out.println("  2. Decrypt");
        System.out.println("  3. Encrypt & Decrypt (verify round-trip)");
        System.out.print("Choice (1/2/3): ");
        int mode = Integer.parseInt(scanner.nextLine().trim());

        // Key input
        System.out.println();
        System.out.println("Enter 64-bit key as 16 hex characters (e.g., 133457799BBCDFF1):");
        System.out.print("Key: ");
        String keyHex = scanner.nextLine().trim().replaceAll("\\s+", "");
        if (keyHex.length() != 16) {
            System.err.println("Error: Key must be exactly 16 hex characters (64 bits).");
            return;
        }

        if (mode == 1 || mode == 3) {
            System.out.println();
            System.out.println("Enter 64-bit plaintext as 16 hex characters (e.g., 0123456789ABCDEF):");
            System.out.print("Plaintext: ");
            String plaintextHex = scanner.nextLine().trim().replaceAll("\\s+", "");
            if (plaintextHex.length() != 16) {
                System.err.println("Error: Plaintext must be exactly 16 hex characters (64 bits).");
                return;
            }

            String cipherHex = DES.encrypt(plaintextHex, keyHex, true);
            System.out.println("*** ENCRYPTION RESULT: " + cipherHex + " ***");

            if (mode == 3) {
                System.out.println("\n--- Now decrypting to verify ---");
                String recoveredHex = DES.decrypt(cipherHex, keyHex, true);
                System.out.println("*** DECRYPTION RESULT: " + recoveredHex + " ***");
                System.out.println("*** Original plaintext:  " + plaintextHex.toUpperCase() + " ***");
                System.out.println("*** Match: " + plaintextHex.equalsIgnoreCase(recoveredHex) + " ***");
            }

        } else if (mode == 2) {
            System.out.println();
            System.out.println("Enter 64-bit ciphertext as 16 hex characters:");
            System.out.print("Ciphertext: ");
            String cipherHex = scanner.nextLine().trim().replaceAll("\\s+", "");
            if (cipherHex.length() != 16) {
                System.err.println("Error: Ciphertext must be exactly 16 hex characters (64 bits).");
                return;
            }

            String plainHex = DES.decrypt(cipherHex, keyHex, true);
            System.out.println("*** DECRYPTION RESULT: " + plainHex + " ***");
        }

        scanner.close();
    }
}
