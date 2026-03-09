/**
 * DES (Data Encryption Standard) Implementation
 * 
 * Takes a 64-bit key and a 64-bit plaintext block, applies DES encryption,
 * and shows all intermediate steps:
 *   - Initial Permutation (IP)
 *   - 16 Feistel Rounds (with expansion, S-box substitution, permutation)
 *   - Final Permutation (IP^-1)
 */
public class DES {

    // ======================== PERMUTATION TABLES ========================

    /** Initial Permutation (IP) table - 64 entries */
    private static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    };

    /** Final Permutation (IP^-1) table - 64 entries */
    private static final int[] IP_INV = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };

    /** Expansion Permutation (E) table - 48 entries */
    private static final int[] E = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };

    /** Permutation (P) table used after S-box substitution - 32 entries */
    private static final int[] P = {
        16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9,
        19, 13, 30,  6, 22, 11,  4, 25
    };

    /** S-Boxes (8 S-boxes, each 4x16) */
    private static final int[][][] S_BOX = {
        // S1
        {
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
        },
        // S2
        {
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
        },
        // S3
        {
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
        },
        // S4
        {
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
        },
        // S5
        {
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
        },
        // S6
        {
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
        },
        // S7
        {
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
        },
        // S8
        {
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6,  2,  0, 14,  9, 11},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
        }
    };

    // ======================== KEY SCHEDULE TABLES ========================

    /** Permuted Choice 1 (PC-1) - 56 entries (drops parity bits) */
    private static final int[] PC1 = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };

    /** Permuted Choice 2 (PC-2) - 48 entries */
    private static final int[] PC2 = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    /** Number of left shifts per round */
    private static final int[] SHIFTS = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    // ======================== UTILITY METHODS ========================

    /**
     * Converts a hex string to a binary string of the specified bit length.
     */
    public static String hexToBin(String hex, int bits) {
        StringBuilder sb = new StringBuilder();
        for (char c : hex.toCharArray()) {
            int val = Integer.parseInt(String.valueOf(c), 16);
            String bin = String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0');
            sb.append(bin);
        }
        String result = sb.toString();
        // Pad or truncate to exact bit length
        if (result.length() < bits) {
            result = String.format("%" + bits + "s", result).replace(' ', '0');
        } else if (result.length() > bits) {
            result = result.substring(0, bits);
        }
        return result;
    }

    /**
     * Converts a binary string to a hex string.
     */
    public static String binToHex(String bin) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4) {
            String nibble = bin.substring(i, Math.min(i + 4, bin.length()));
            sb.append(Integer.toHexString(Integer.parseInt(nibble, 2)).toUpperCase());
        }
        return sb.toString();
    }

    /**
     * Applies a permutation table to the input bit string.
     */
    public static String permute(String input, int[] table) {
        StringBuilder sb = new StringBuilder();
        for (int pos : table) {
            sb.append(input.charAt(pos - 1)); // tables are 1-based
        }
        return sb.toString();
    }

    /**
     * Left circular shift on a bit string.
     */
    public static String leftShift(String bits, int n) {
        n = n % bits.length();
        return bits.substring(n) + bits.substring(0, n);
    }

    /**
     * XOR two equal-length binary strings.
     */
    public static String xor(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return sb.toString();
    }

    // ======================== KEY SCHEDULE ========================

    /**
     * Generates the 16 round subkeys from the 64-bit key.
     * @param keyBin 64-bit binary key string
     * @return array of 16 subkeys, each 48 bits
     */
    public static String[] generateSubkeys(String keyBin, boolean verbose) {
        if (verbose) {
            System.out.println("\n========== KEY SCHEDULE ==========");
            System.out.println("Original Key (64-bit): " + keyBin + " [" + binToHex(keyBin) + "]");
        }

        // Apply PC-1 to get 56-bit key
        String key56 = permute(keyBin, PC1);
        if (verbose) {
            System.out.println("After PC-1 (56-bit):   " + key56 + " [" + binToHex(key56) + "]");
        }

        // Split into C0 and D0 (28 bits each)
        String C = key56.substring(0, 28);
        String D = key56.substring(28, 56);

        if (verbose) {
            System.out.println("C0 = " + C);
            System.out.println("D0 = " + D);
        }

        String[] subkeys = new String[16];

        for (int i = 0; i < 16; i++) {
            C = leftShift(C, SHIFTS[i]);
            D = leftShift(D, SHIFTS[i]);

            String CD = C + D;
            subkeys[i] = permute(CD, PC2);

            if (verbose) {
                System.out.printf("Round %2d: C%d = %s  D%d = %s  => K%d = %s [%s]%n",
                    i + 1, i + 1, C, i + 1, D, i + 1, subkeys[i], binToHex(subkeys[i]));
            }
        }

        return subkeys;
    }

    // ======================== FEISTEL FUNCTION ========================

    /**
     * The Feistel function f(R, K).
     * @param R 32-bit right half
     * @param K 48-bit subkey
     * @return 32-bit result
     */
    public static String feistel(String R, String K, int round, boolean verbose) {
        // 1. Expansion
        String expanded = permute(R, E);
        if (verbose) {
            System.out.println("    E(R" + (round - 1) + ")        = " + expanded + " [" + binToHex(expanded) + "]");
            System.out.println("    K" + round + "            = " + K + " [" + binToHex(K) + "]");
        }

        // 2. XOR with subkey
        String xored = xor(expanded, K);
        if (verbose) {
            System.out.println("    E(R) XOR K   = " + xored + " [" + binToHex(xored) + "]");
        }

        // 3. S-box substitution
        StringBuilder sboxResult = new StringBuilder();
        if (verbose) System.out.print("    S-box output = ");
        for (int i = 0; i < 8; i++) {
            String block = xored.substring(i * 6, (i + 1) * 6);
            int row = Integer.parseInt("" + block.charAt(0) + block.charAt(5), 2);
            int col = Integer.parseInt(block.substring(1, 5), 2);
            int val = S_BOX[i][row][col];
            String valBin = String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0');
            sboxResult.append(valBin);
        }
        if (verbose) {
            System.out.println(sboxResult.toString() + " [" + binToHex(sboxResult.toString()) + "]");
        }

        // 4. Permutation P
        String result = permute(sboxResult.toString(), P);
        if (verbose) {
            System.out.println("    P(S-box)     = " + result + " [" + binToHex(result) + "]");
        }

        return result;
    }

    // ======================== DES ENCRYPT ========================

    /**
     * Performs DES encryption on a 64-bit plaintext block with a 64-bit key.
     * @param plaintextHex 16 hex characters (64 bits)
     * @param keyHex 16 hex characters (64 bits)
     * @param verbose if true, print all intermediate steps
     * @return ciphertext as hex string
     */
    public static String encrypt(String plaintextHex, String keyHex, boolean verbose) {
        String plainBin = hexToBin(plaintextHex, 64);
        String keyBin = hexToBin(keyHex, 64);

        if (verbose) {
            System.out.println("\n##################################################");
            System.out.println("           DES ENCRYPTION");
            System.out.println("##################################################");
            System.out.println("Plaintext (hex): " + plaintextHex.toUpperCase());
            System.out.println("Plaintext (bin): " + plainBin);
            System.out.println("Key       (hex): " + keyHex.toUpperCase());
            System.out.println("Key       (bin): " + keyBin);
        }

        // Generate subkeys
        String[] subkeys = generateSubkeys(keyBin, verbose);

        // Initial Permutation
        String permuted = permute(plainBin, IP);
        if (verbose) {
            System.out.println("\n========== INITIAL PERMUTATION ==========");
            System.out.println("After IP: " + permuted + " [" + binToHex(permuted) + "]");
        }

        // Split into L0 and R0
        String L = permuted.substring(0, 32);
        String R = permuted.substring(32, 64);

        if (verbose) {
            System.out.println("L0 = " + L + " [" + binToHex(L) + "]");
            System.out.println("R0 = " + R + " [" + binToHex(R) + "]");
        }

        // 16 Feistel rounds
        if (verbose) {
            System.out.println("\n========== 16 FEISTEL ROUNDS ==========");
        }

        for (int i = 0; i < 16; i++) {
            if (verbose) {
                System.out.println("\n--- Round " + (i + 1) + " ---");
            }

            String fResult = feistel(R, subkeys[i], i + 1, verbose);
            String newR = xor(L, fResult);

            if (verbose) {
                System.out.println("    L" + (i + 1) + " = R" + i + " = " + R + " [" + binToHex(R) + "]");
                System.out.println("    R" + (i + 1) + " = L" + i + " XOR f(R" + i + ",K" + (i + 1) + ") = " + newR + " [" + binToHex(newR) + "]");
            }

            L = R;
            R = newR;
        }

        // Combine R16L16 (note: reversed!)
        String combined = R + L;
        if (verbose) {
            System.out.println("\n========== PRE-OUTPUT ==========");
            System.out.println("R16L16 (before final permutation): " + combined + " [" + binToHex(combined) + "]");
        }

        // Final Permutation (IP^-1)
        String cipherBin = permute(combined, IP_INV);
        String cipherHex = binToHex(cipherBin);

        if (verbose) {
            System.out.println("\n========== FINAL PERMUTATION (IP^-1) ==========");
            System.out.println("Ciphertext (bin): " + cipherBin);
            System.out.println("Ciphertext (hex): " + cipherHex);
            System.out.println("##################################################\n");
        }

        return cipherHex;
    }

    /**
     * Performs DES decryption on a 64-bit ciphertext block with a 64-bit key.
     * Decryption is the same as encryption but with subkeys in reverse order.
     */
    public static String decrypt(String ciphertextHex, String keyHex, boolean verbose) {
        String cipherBin = hexToBin(ciphertextHex, 64);
        String keyBin = hexToBin(keyHex, 64);

        if (verbose) {
            System.out.println("\n##################################################");
            System.out.println("           DES DECRYPTION");
            System.out.println("##################################################");
            System.out.println("Ciphertext (hex): " + ciphertextHex.toUpperCase());
            System.out.println("Ciphertext (bin): " + cipherBin);
            System.out.println("Key        (hex): " + keyHex.toUpperCase());
            System.out.println("Key        (bin): " + keyBin);
        }

        // Generate subkeys
        String[] subkeys = generateSubkeys(keyBin, verbose);

        // Initial Permutation
        String permuted = permute(cipherBin, IP);
        if (verbose) {
            System.out.println("\n========== INITIAL PERMUTATION ==========");
            System.out.println("After IP: " + permuted + " [" + binToHex(permuted) + "]");
        }

        String L = permuted.substring(0, 32);
        String R = permuted.substring(32, 64);

        if (verbose) {
            System.out.println("L0 = " + L + " [" + binToHex(L) + "]");
            System.out.println("R0 = " + R + " [" + binToHex(R) + "]");
        }

        // 16 rounds with subkeys in reverse
        if (verbose) {
            System.out.println("\n========== 16 FEISTEL ROUNDS (Reverse Key Order) ==========");
        }

        for (int i = 0; i < 16; i++) {
            if (verbose) {
                System.out.println("\n--- Round " + (i + 1) + " (using K" + (16 - i) + ") ---");
            }

            String fResult = feistel(R, subkeys[15 - i], 16 - i, verbose);
            String newR = xor(L, fResult);

            if (verbose) {
                System.out.println("    L" + (i + 1) + " = R" + i + " = " + R + " [" + binToHex(R) + "]");
                System.out.println("    R" + (i + 1) + " = L" + i + " XOR f = " + newR + " [" + binToHex(newR) + "]");
            }

            L = R;
            R = newR;
        }

        String combined = R + L;
        if (verbose) {
            System.out.println("\n========== PRE-OUTPUT ==========");
            System.out.println("R16L16: " + combined + " [" + binToHex(combined) + "]");
        }

        String plainBin = permute(combined, IP_INV);
        String plainHex = binToHex(plainBin);

        if (verbose) {
            System.out.println("\n========== FINAL PERMUTATION (IP^-1) ==========");
            System.out.println("Plaintext (bin): " + plainBin);
            System.out.println("Plaintext (hex): " + plainHex);
            System.out.println("##################################################\n");
        }

        return plainHex;
    }
}
