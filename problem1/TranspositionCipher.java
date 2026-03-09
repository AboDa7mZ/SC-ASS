/**
 * Transposition Cipher (Columnar Transposition)
 * Rearranges the characters of the message according to a numeric permutation key.
 * 
 * Example: key = "3 1 2" means 3 columns; read-off order is column2, column3, column1.
 * 
 * The key is provided as a comma-separated or space-separated list of integers
 * representing the column order (1-based).
 * e.g., "3 1 4 2" means 4 columns and the read-off order is col2, col4, col1, col3.
 */
public class TranspositionCipher {

    private final int[] key; // permutation array (0-based internally)

    /**
     * @param keyStr A space-separated or comma-separated string of integers (1-based)
     *              representing the permutation. e.g., "3 1 4 2"
     */
    public TranspositionCipher(String keyStr) {
        keyStr = keyStr.trim().replaceAll(",", " ").replaceAll("\\s+", " ");
        String[] parts = keyStr.split(" ");
        if (parts.length == 0) {
            throw new IllegalArgumentException("Permutation key must not be empty.");
        }

        this.key = new int[parts.length];
        boolean[] used = new boolean[parts.length];

        for (int i = 0; i < parts.length; i++) {
            int val = Integer.parseInt(parts[i]);
            if (val < 1 || val > parts.length) {
                throw new IllegalArgumentException(
                    "Permutation values must be between 1 and " + parts.length + ". Got: " + val);
            }
            if (used[val - 1]) {
                throw new IllegalArgumentException("Duplicate value in permutation: " + val);
            }
            used[val - 1] = true;
            this.key[i] = val - 1; // convert to 0-based
        }
    }

    /**
     * Encrypts the given plaintext using columnar transposition.
     */
    public String encrypt(String plaintext) {
        int numCols = key.length;
        // Pad the plaintext so its length is a multiple of numCols
        int paddedLen = plaintext.length();
        if (paddedLen % numCols != 0) {
            paddedLen = paddedLen + (numCols - paddedLen % numCols);
        }

        // Fill the grid row by row
        char[][] grid = new char[paddedLen / numCols][numCols];
        for (int i = 0; i < paddedLen; i++) {
            int row = i / numCols;
            int col = i % numCols;
            if (i < plaintext.length()) {
                grid[row][col] = plaintext.charAt(i);
            } else {
                grid[row][col] = 'X'; // padding character
            }
        }

        // Read off columns in the order specified by the key
        // key[i] = k means column i has label k
        // We need to read columns in order of their labels: 0, 1, 2, ...
        // Find which column index has label 0, then 1, etc.
        int[] readOrder = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            readOrder[key[i]] = i;
        }

        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < numCols; col++) {
            int actualCol = readOrder[col];
            for (int row = 0; row < grid.length; row++) {
                sb.append(grid[row][actualCol]);
            }
        }
        return sb.toString();
    }

    /**
     * Decrypts the given ciphertext using columnar transposition.
     */
    public String decrypt(String ciphertext) {
        int numCols = key.length;
        int numRows = ciphertext.length() / numCols;

        if (ciphertext.length() % numCols != 0) {
            throw new IllegalArgumentException(
                "Ciphertext length must be a multiple of the key length for transposition decryption.");
        }

        // Determine the read order (same as encryption)
        int[] readOrder = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            readOrder[key[i]] = i;
        }

        // Fill the grid column by column in the read order
        char[][] grid = new char[numRows][numCols];
        int idx = 0;
        for (int col = 0; col < numCols; col++) {
            int actualCol = readOrder[col];
            for (int row = 0; row < numRows; row++) {
                grid[row][actualCol] = ciphertext.charAt(idx++);
            }
        }

        // Read the grid row by row
        StringBuilder sb = new StringBuilder();
        for (int row = 0; row < numRows; row++) {
            for (int col = 0; col < numCols; col++) {
                sb.append(grid[row][col]);
            }
        }

        // Remove trailing 'X' padding
        String result = sb.toString();
        while (result.endsWith("X")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    public int[] getKey() {
        int[] result = new int[key.length];
        for (int i = 0; i < key.length; i++) {
            result[i] = key[i] + 1; // return 1-based
        }
        return result;
    }
}
