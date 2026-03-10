import java.util.Scanner;

public class DESMain {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("==============================");
        System.out.println("     DES Encryption Tool");
        System.out.println("==============================");
        System.out.println();

        System.out.println("Choose mode:");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.println("3. Encrypt then Decrypt (round-trip test)");
        System.out.print("Enter choice: ");
        int mode = Integer.parseInt(sc.nextLine().trim());

        System.out.println();
        System.out.println("Enter 64-bit key (16 hex characters):");
        System.out.print("Key: ");
        String key = sc.nextLine().trim();

        if (key.length() != 16) {
            System.out.println("Error: key must be 16 hex characters.");
            return;
        }

        if (mode == 1 || mode == 3) {
            System.out.println();
            System.out.println("Enter 64-bit plaintext (16 hex characters):");
            System.out.print("Plaintext: ");
            String plain = sc.nextLine().trim();

            if (plain.length() != 16) {
                System.out.println("Error: plaintext must be 16 hex characters.");
                return;
            }

            String cipher = DES.encrypt(plain, key, true);
            System.out.println("==> Ciphertext: " + cipher);

            if (mode == 3) {
                System.out.println("\n--- Now decrypting to verify ---");
                String recovered = DES.decrypt(cipher, key, true);
                System.out.println("==> Recovered plaintext: " + recovered);
                System.out.println("==> Original:           " + plain.toUpperCase());
                System.out.println("==> Match: " + plain.equalsIgnoreCase(recovered));
            }

        } else if (mode == 2) {
            System.out.println();
            System.out.println("Enter 64-bit ciphertext (16 hex characters):");
            System.out.print("Ciphertext: ");
            String cipher = sc.nextLine().trim();

            if (cipher.length() != 16) {
                System.out.println("Error: ciphertext must be 16 hex characters.");
                return;
            }

            String plain = DES.decrypt(cipher, key, true);
            System.out.println("==> Plaintext: " + plain);
        }

        sc.close();
    }
}
