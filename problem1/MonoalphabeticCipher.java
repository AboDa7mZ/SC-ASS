import java.util.HashMap;
import java.util.Map;

/**
 * Monoalphabetic Substitution Cipher
 * Replaces each letter with another fixed letter based on a substitution key.
 * The key is a 26-character string representing the substitution alphabet.
 * e.g., key = "QWERTYUIOPASDFGHJKLZXCVBNM"
 *       means A->Q, B->W, C->E, D->R, ...
 */
public class MonoalphabeticCipher {

    private final String key; // 26 uppercase letters representing substitution alphabet
    private final Map<Character, Character> encryptMap;
    private final Map<Character, Character> decryptMap;

    /**
     * @param key A 26-character string of unique uppercase letters (A-Z).
     */
    public MonoalphabeticCipher(String key) {
        key = key.toUpperCase();
        if (key.length() != 26) {
            throw new IllegalArgumentException("Substitution key must be exactly 26 characters.");
        }
        // Validate uniqueness
        boolean[] seen = new boolean[26];
        for (char c : key.toCharArray()) {
            if (c < 'A' || c > 'Z') {
                throw new IllegalArgumentException("Key must contain only letters A-Z.");
            }
            if (seen[c - 'A']) {
                throw new IllegalArgumentException("Key must contain each letter exactly once. Duplicate: " + c);
            }
            seen[c - 'A'] = true;
        }

        this.key = key;
        this.encryptMap = new HashMap<>();
        this.decryptMap = new HashMap<>();

        for (int i = 0; i < 26; i++) {
            char plain = (char) ('A' + i);
            char cipher = key.charAt(i);
            encryptMap.put(plain, cipher);
            decryptMap.put(cipher, plain);
        }
    }

    /**
     * Encrypts the given plaintext using the monoalphabetic substitution cipher.
     * Non-letter characters are preserved as-is.
     */
    public String encrypt(String plaintext) {
        StringBuilder sb = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sb.append(encryptMap.get(c));
            } else if (Character.isLowerCase(c)) {
                sb.append(Character.toLowerCase(encryptMap.get(Character.toUpperCase(c))));
            } else {
                sb.append(c); // preserve non-letter characters
            }
        }
        return sb.toString();
    }

    /**
     * Decrypts the given ciphertext using the monoalphabetic substitution cipher.
     * Non-letter characters are preserved as-is.
     */
    public String decrypt(String ciphertext) {
        StringBuilder sb = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sb.append(decryptMap.get(c));
            } else if (Character.isLowerCase(c)) {
                sb.append(Character.toLowerCase(decryptMap.get(Character.toUpperCase(c))));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public String getKey() {
        return key;
    }
}
