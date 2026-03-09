/**
 * Polyalphabetic Cipher (Vigenère Cipher)
 * Uses a keyword to shift characters with a repeating pattern.
 * Each letter in the keyword determines the shift for the corresponding plaintext letter.
 * A=0, B=1, C=2, ..., Z=25
 */
public class PolyalphabeticCipher {

    private final String keyword;

    /**
     * @param keyword A string of letters (A-Z) used as the repeating key.
     */
    public PolyalphabeticCipher(String keyword) {
        keyword = keyword.toUpperCase();
        if (keyword.isEmpty()) {
            throw new IllegalArgumentException("Keyword must not be empty.");
        }
        for (char c : keyword.toCharArray()) {
            if (c < 'A' || c > 'Z') {
                throw new IllegalArgumentException("Keyword must contain only letters A-Z.");
            }
        }
        this.keyword = keyword;
    }

    /**
     * Encrypts the given plaintext using the Vigenère cipher.
     * Non-letter characters are preserved and do not advance the key index.
     */
    public String encrypt(String plaintext) {
        StringBuilder sb = new StringBuilder();
        int keyIndex = 0;

        for (char c : plaintext.toCharArray()) {
            if (Character.isLetter(c)) {
                int shift = keyword.charAt(keyIndex % keyword.length()) - 'A';
                if (Character.isUpperCase(c)) {
                    sb.append((char) ('A' + (c - 'A' + shift) % 26));
                } else {
                    sb.append((char) ('a' + (c - 'a' + shift) % 26));
                }
                keyIndex++;
            } else {
                sb.append(c); // preserve non-letter characters
            }
        }
        return sb.toString();
    }

    /**
     * Decrypts the given ciphertext using the Vigenère cipher.
     * Non-letter characters are preserved and do not advance the key index.
     */
    public String decrypt(String ciphertext) {
        StringBuilder sb = new StringBuilder();
        int keyIndex = 0;

        for (char c : ciphertext.toCharArray()) {
            if (Character.isLetter(c)) {
                int shift = keyword.charAt(keyIndex % keyword.length()) - 'A';
                if (Character.isUpperCase(c)) {
                    sb.append((char) ('A' + (c - 'A' - shift + 26) % 26));
                } else {
                    sb.append((char) ('a' + (c - 'a' - shift + 26) % 26));
                }
                keyIndex++;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public String getKeyword() {
        return keyword;
    }
}
