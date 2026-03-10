
public class TranspositionCipher {

    private int[] key;
    private int numCols;

    public TranspositionCipher(String keyStr) {
        String[] parts = keyStr.trim().split(" ");
        numCols = parts.length;
        key = new int[numCols];

        for (int i = 0; i < numCols; i++) {
            key[i] = Integer.parseInt(parts[i]) - 1;
        }
    }

    public String encrypt(String text) {
        while (text.length() % numCols != 0) {
            text += 'X';
        }

        int numRows = text.length() / numCols;

        char[][] grid = new char[numRows][numCols];
        int index = 0;
        for (int r = 0; r < numRows; r++) {
            for (int c = 0; c < numCols; c++) {
                grid[r][c] = text.charAt(index);
                index++;
            }
        }

        int[] readOrder = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            readOrder[key[i]] = i;
        }

        String result = "";
        for (int c = 0; c < numCols; c++) {
            int col = readOrder[c];
            for (int r = 0; r < numRows; r++) {
                result += grid[r][col];
            }
        }

        return result;
    }

    public String decrypt(String text) {
        int numRows = text.length() / numCols;

        int[] readOrder = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            readOrder[key[i]] = i;
        }

        char[][] grid = new char[numRows][numCols];
        int index = 0;
        for (int c = 0; c < numCols; c++) {
            int col = readOrder[c];
            for (int r = 0; r < numRows; r++) {
                grid[r][col] = text.charAt(index);
                index++;
            }
        }

        String result = "";
        for (int r = 0; r < numRows; r++) {
            for (int c = 0; c < numCols; c++) {
                result += grid[r][c];
            }
        }

        while (result.endsWith("X")) {
            result = result.substring(0, result.length() - 1);
        }

        return result;
    }

    public int[] getKey() {
        int[] result = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            result[i] = key[i] + 1;
        }
        return result;
    }
}
