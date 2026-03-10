import java.io.*;
import java.util.Scanner;


public class ClassicalEncryptionTool {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("====================================");
        System.out.println("    Classical Encryption Tool");
        System.out.println("====================================");

        System.out.println("\nSelect cipher type:");
        System.out.println("1. Monoalphabetic Substitution Cipher");
        System.out.println("2. Polyalphabetic Cipher (Vigenere)");
        System.out.println("3. Transposition Cipher");
        System.out.print("Enter choice: ");
        int cipherType = Integer.parseInt(sc.nextLine().trim());

        System.out.println("\nSelect mode:");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.print("Enter choice: ");
        int mode = Integer.parseInt(sc.nextLine().trim());

        System.out.print("\nEnter input file path: ");
        String inputFile = sc.nextLine().trim();
        System.out.print("Enter output file path: ");
        String outputFile = sc.nextLine().trim();

        String text = readFile(inputFile);
        if (text == null) {
            System.out.println("Error: could not read file!");
            return;
        }

        String result = "";

        if (cipherType == 1) {
            System.out.println("\n--- Monoalphabetic Cipher ---");
            System.out.print("Enter substitution key (26 letters, e.g. QWERTYUIOPASDFGHJKLZXCVBNM): ");
            String key = sc.nextLine().trim();

            MonoalphabeticCipher cipher = new MonoalphabeticCipher(key);

            System.out.print("Plain:  ");
            for (char c = 'A'; c <= 'Z'; c++) System.out.print(c + " ");
            System.out.println();
            System.out.print("Cipher: ");
            for (int i = 0; i < cipher.getKey().length(); i++)
                System.out.print(cipher.getKey().charAt(i) + " ");
            System.out.println();

            if (mode == 1)
                result = cipher.encrypt(text);
            else
                result = cipher.decrypt(text);

        } else if (cipherType == 2) {
            System.out.println("\n--- Vigenere Cipher ---");
            System.out.print("Enter keyword: ");
            String keyword = sc.nextLine().trim();

            PolyalphabeticCipher cipher = new PolyalphabeticCipher(keyword);
            System.out.println("Using keyword: " + cipher.getKeyword());

            if (mode == 1)
                result = cipher.encrypt(text);
            else
                result = cipher.decrypt(text);

        } else if (cipherType == 3) {
            System.out.println("\n--- Transposition Cipher ---");
            System.out.print("Enter permutation key (e.g. 3 1 4 2): ");
            String keyStr = sc.nextLine().trim();

            TranspositionCipher cipher = new TranspositionCipher(keyStr);

            System.out.print("Key order: ");
            for (int k : cipher.getKey()) System.out.print(k + " ");
            System.out.println();

            if (mode == 1)
                result = cipher.encrypt(text);
            else
                result = cipher.decrypt(text);

        } else {
            System.out.println("Invalid choice!");
            return;
        }

        writeFile(outputFile, result);

        System.out.println("\n====================================");
        if (mode == 1)
            System.out.println("Encryption done! Output: " + outputFile);
        else
            System.out.println("Decryption done! Output: " + outputFile);
        System.out.println("====================================");
    }

    static String readFile(String filename) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            String text = "";
            String line;
            while ((line = br.readLine()) != null) {
                text += line + "\n";
            }
            br.close();
            if (text.endsWith("\n"))
                text = text.substring(0, text.length() - 1);
            return text;
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            return null;
        }
    }

    static void writeFile(String filename, String text) {
        try {
            PrintWriter pw = new PrintWriter(new FileWriter(filename));
            pw.print(text);
            pw.close();
        } catch (IOException e) {
            System.out.println("Error writing file: " + e.getMessage());
        }
    }
}
