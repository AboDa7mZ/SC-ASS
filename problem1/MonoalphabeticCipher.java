
public class MonoalphabeticCipher {

    private String key;

    public MonoalphabeticCipher(String key) {
        this.key = key.toUpperCase();
    }

    public String encrypt(String text) {
        String result = "";

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);

            if (ch >= 'A' && ch <= 'Z') {
                int pos = ch - 'A';
                result += key.charAt(pos);
            } else if (ch >= 'a' && ch <= 'z') {
                int pos = ch - 'a';
                result += Character.toLowerCase(key.charAt(pos));
            } else {
                result += ch;
            }
        }

        return result;
    }

    public String decrypt(String text) {
        String result = "";

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);

            if (ch >= 'A' && ch <= 'Z') {
                int pos = key.indexOf(ch);
                result += (char) ('A' + pos);
            } else if (ch >= 'a' && ch <= 'z') {
                int pos = key.indexOf(Character.toUpperCase(ch));
                result += (char) ('a' + pos);
            } else {
                result += ch;
            }
        }

        return result;
    }

    public String getKey() {
        return key;
    }
}
