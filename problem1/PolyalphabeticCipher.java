
public class PolyalphabeticCipher {

    private String keyword;

    public PolyalphabeticCipher(String keyword) {
        this.keyword = keyword.toUpperCase();
    }

    public String encrypt(String text) {
        String result = "";
        int keyIndex = 0;

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);

            if (ch >= 'A' && ch <= 'Z') {
                int shift = keyword.charAt(keyIndex % keyword.length()) - 'A';
                char encrypted = (char) ('A' + (ch - 'A' + shift) % 26);
                result += encrypted;
                keyIndex++;
            } else if (ch >= 'a' && ch <= 'z') {
                int shift = keyword.charAt(keyIndex % keyword.length()) - 'A';
                char encrypted = (char) ('a' + (ch - 'a' + shift) % 26);
                result += encrypted;
                keyIndex++;
            } else {
                result += ch;
            }
        }

        return result;
    }

    public String decrypt(String text) {
        String result = "";
        int keyIndex = 0;

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);

            if (ch >= 'A' && ch <= 'Z') {
                int shift = keyword.charAt(keyIndex % keyword.length()) - 'A';
                char decrypted = (char) ('A' + (ch - 'A' - shift + 26) % 26);
                result += decrypted;
                keyIndex++;
            } else if (ch >= 'a' && ch <= 'z') {
                int shift = keyword.charAt(keyIndex % keyword.length()) - 'A';
                char decrypted = (char) ('a' + (ch - 'a' - shift + 26) % 26);
                result += decrypted;
                keyIndex++;
            } else {
                result += ch;
            }
        }

        return result;
    }

    public String getKeyword() {
        return keyword;
    }
}
