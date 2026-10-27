// Prueba SecretCrypto contra decrypt/test-vectors.txt.
// Uso: javac SecretCrypto.java SecretCryptoTest.java && java SecretCryptoTest
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class SecretCryptoTest {
    static final String[] ALGORITHMS = {"aes256gcm", "chacha20poly1305", "aes256cbc-hmac", "aes128gcm", "aes256cbc", "3des", "base64"};

    public static void main(String[] args) throws Exception {
        Map<String, String> vec = new HashMap<>();
        for (String line : Files.readAllLines(Path.of("..", "test-vectors.txt"), StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) continue;
            int i = line.indexOf('=');
            vec.put(line.substring(0, i), line.substring(i + 1));
        }
        String key = vec.get("masterKey");
        String plain = vec.get("plainText");
        for (String alg : ALGORITHMS) {
            check(SecretCrypto.decrypt(vec.get(alg), key).equals(plain), alg);
            check(SecretCrypto.decrypt(vec.get(alg + ".raw"), key, alg).equals(plain), alg + ".raw");
        }
        expectError(() -> SecretCrypto.decrypt(vec.get("tampered"), key));
        expectError(() -> SecretCrypto.decrypt(vec.get("aes256gcm"), key, "aes128gcm"));
        System.out.println("Java: " + (ALGORITHMS.length * 2 + 2) + " pruebas correctas");
    }

    interface Action { void run() throws Exception; }

    static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("Falló: " + name);
    }

    static void expectError(Action action) {
        try { action.run(); } catch (Exception e) { return; }
        throw new AssertionError("Se esperaba un error");
    }
}
