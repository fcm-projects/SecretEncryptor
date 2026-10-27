// SecretCrypto - Descifra los valores generados con SecretEncryptor.
//
// Formato del valor:
//   con prefijo:  "<algoritmo>:<Base64>"  -> decrypt(valor, llave)
//   sin prefijo:  "<Base64>"              -> decrypt(valor, llave, algoritmo)
//
// Algoritmos y estructura del contenido:
//   aes256gcm         AES-256-GCM               nonce(12) || cifrado || tag(16)
//   chacha20poly1305  ChaCha20-Poly1305         nonce(12) || cifrado || tag(16)   (Android 9+, API 28)
//   aes256cbc-hmac    AES-256-CBC + HMAC-SHA256 IV(16) || cifrado || HMAC(32)
//   aes128gcm         AES-128-GCM               nonce(12) || cifrado || tag(16)
//   aes256cbc         AES-256-CBC sin HMAC      IV(16) || cifrado
//   3des              3DES-CBC                  IV(8) || cifrado
//   base64            Base64                    texto codificado, sin llave
//
// Android: java.util.Base64 requiere API 26+. En API < 26 usar android.util.Base64 (NO_WRAP).
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SecretCrypto {

    private SecretCrypto() { }

    /** Descifra un valor con prefijo "<algoritmo>:". */
    public static String decrypt(String value, String masterKeyBase64) throws Exception {
        return decrypt(value, masterKeyBase64, null);
    }

    /** Descifra un valor indicando el algoritmo. Si el valor también trae prefijo, ambos deben coincidir. */
    public static String decrypt(String value, String masterKeyBase64, String algorithm) throws Exception {
        String v = value.trim();
        String body = v;
        int sep = v.indexOf(':');
        if (sep > 0) {
            String prefix = v.substring(0, sep);
            if (algorithm != null && !algorithm.equals(prefix)) {
                throw new IllegalArgumentException("El prefijo (" + prefix + ") no coincide con el algoritmo indicado (" + algorithm + ")");
            }
            algorithm = prefix;
            body = v.substring(sep + 1);
        }
        if (algorithm == null) throw new IllegalArgumentException("El valor no tiene prefijo: indica el algoritmo");

        byte[] payload = Base64.getDecoder().decode(body);
        if (algorithm.equals("base64")) return new String(payload, StandardCharsets.UTF_8);

        byte[] mk = parseMasterKey(masterKeyBase64);
        byte[] data;
        switch (algorithm) {
            case "aes256gcm":
                data = aead("AES/GCM/NoPadding", "AES", deriveKey(mk, "aes256gcm"), payload);
                break;
            case "chacha20poly1305":
                data = aead("ChaCha20-Poly1305", "ChaCha20", deriveKey(mk, "chacha20"), payload);
                break;
            case "aes256cbc-hmac": {
                byte[] ivct = Arrays.copyOfRange(payload, 0, payload.length - 32);
                byte[] tag = Arrays.copyOfRange(payload, payload.length - 32, payload.length);
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(deriveKey(mk, "mac"), "HmacSHA256"));
                if (!MessageDigest.isEqual(mac.doFinal(ivct), tag)) throw new SecurityException("Integridad no válida");
                data = cbc("AES/CBC/PKCS5Padding", "AES", deriveKey(mk, "enc"), ivct, 16);
                break;
            }
            case "aes128gcm":
                data = aead("AES/GCM/NoPadding", "AES", Arrays.copyOf(deriveKey(mk, "aes128gcm"), 16), payload);
                break;
            case "aes256cbc":
                data = cbc("AES/CBC/PKCS5Padding", "AES", deriveKey(mk, "aes256cbc"), payload, 16);
                break;
            case "3des":
                data = cbc("DESede/CBC/PKCS5Padding", "DESede", Arrays.copyOf(deriveKey(mk, "3des"), 24), payload, 8);
                break;
            default:
                throw new IllegalArgumentException("Algoritmo no soportado: " + algorithm);
        }
        return new String(data, StandardCharsets.UTF_8);
    }

    private static byte[] deriveKey(byte[] masterKey, String label) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(masterKey, "HmacSHA256"));
        return mac.doFinal(label.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] parseMasterKey(String masterKeyBase64) {
        byte[] key = Base64.getDecoder().decode(masterKeyBase64.trim());
        if (key.length != 32) throw new IllegalArgumentException("Llave maestra inválida: debe tener 32 bytes");
        return key;
    }

    private static byte[] cbc(String transformation, String keyAlg, byte[] key, byte[] ivAndCipher, int ivSize) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlg), new IvParameterSpec(Arrays.copyOfRange(ivAndCipher, 0, ivSize)));
        return cipher.doFinal(Arrays.copyOfRange(ivAndCipher, ivSize, ivAndCipher.length));
    }

    private static byte[] aead(String transformation, String keyAlg, byte[] key, byte[] payload) throws Exception {
        byte[] nonce = Arrays.copyOfRange(payload, 0, 12);
        byte[] cipherAndTag = Arrays.copyOfRange(payload, 12, payload.length);
        Cipher cipher = Cipher.getInstance(transformation);
        if (keyAlg.equals("AES")) {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlg), new GCMParameterSpec(128, nonce));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlg), new IvParameterSpec(nonce));
        }
        return cipher.doFinal(cipherAndTag);
    }
}
