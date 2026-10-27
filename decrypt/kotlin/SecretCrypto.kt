// SecretCrypto - Descifra los valores generados con SecretEncryptor (Kotlin, Android).
//
// Formato del valor:
//   con prefijo:  "<algoritmo>:<Base64>"  -> SecretCrypto.decrypt(valor, llave)
//   sin prefijo:  "<Base64>"              -> SecretCrypto.decrypt(valor, llave, "aes256gcm")
//
// Algoritmos: aes256gcm, chacha20poly1305 (API 28+), aes256cbc-hmac, aes128gcm,
//             aes256cbc, 3des, base64 (sin llave).
import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object SecretCrypto {

    /**
     * Descifra [value]. Si trae prefijo "<algoritmo>:", se usa ese algoritmo;
     * si no, se usa [algorithm]. Cuando se indican ambos, deben coincidir.
     */
    fun decrypt(value: String, masterKeyBase64: String, algorithm: String? = null): String {
        val v = value.trim()
        val sep = v.indexOf(':')
        val prefix = if (sep > 0) v.substring(0, sep) else null
        require(prefix == null || algorithm == null || prefix == algorithm) {
            "El prefijo ($prefix) no coincide con el algoritmo indicado ($algorithm)"
        }
        val alg = prefix ?: algorithm ?: throw IllegalArgumentException("El valor no tiene prefijo: indica el algoritmo")
        val body = if (prefix != null) v.substring(sep + 1) else v
        val payload = Base64.decode(body, Base64.NO_WRAP)
        if (alg == "base64") return String(payload, Charsets.UTF_8)

        val mk = parseMasterKey(masterKeyBase64)
        val data = when (alg) {
            "aes256gcm" -> aead("AES/GCM/NoPadding", "AES", deriveKey(mk, "aes256gcm"), payload)
            "chacha20poly1305" -> aead("ChaCha20-Poly1305", "ChaCha20", deriveKey(mk, "chacha20"), payload)
            "aes256cbc-hmac" -> {
                val ivct = payload.copyOfRange(0, payload.size - 32)
                val tag = payload.copyOfRange(payload.size - 32, payload.size)
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(deriveKey(mk, "mac"), "HmacSHA256"))
                if (!MessageDigest.isEqual(mac.doFinal(ivct), tag)) throw SecurityException("Integridad no válida")
                cbc("AES/CBC/PKCS5Padding", "AES", deriveKey(mk, "enc"), ivct, 16)
            }
            "aes128gcm" -> aead("AES/GCM/NoPadding", "AES", deriveKey(mk, "aes128gcm").copyOf(16), payload)
            "aes256cbc" -> cbc("AES/CBC/PKCS5Padding", "AES", deriveKey(mk, "aes256cbc"), payload, 16)
            "3des" -> cbc("DESede/CBC/PKCS5Padding", "DESede", deriveKey(mk, "3des").copyOf(24), payload, 8)
            else -> throw IllegalArgumentException("Algoritmo no soportado: $alg")
        }
        return String(data, Charsets.UTF_8)
    }

    private fun deriveKey(masterKey: ByteArray, label: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(masterKey, "HmacSHA256"))
        return mac.doFinal(label.toByteArray(Charsets.UTF_8))
    }

    private fun parseMasterKey(masterKeyBase64: String): ByteArray {
        val key = Base64.decode(masterKeyBase64.trim(), Base64.NO_WRAP)
        require(key.size == 32) { "Llave maestra inválida: debe tener 32 bytes" }
        return key
    }

    private fun cbc(transformation: String, keyAlg: String, key: ByteArray, ivAndCipher: ByteArray, ivSize: Int): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, keyAlg), IvParameterSpec(ivAndCipher.copyOfRange(0, ivSize)))
        return cipher.doFinal(ivAndCipher.copyOfRange(ivSize, ivAndCipher.size))
    }

    private fun aead(transformation: String, keyAlg: String, key: ByteArray, payload: ByteArray): ByteArray {
        val nonce = payload.copyOfRange(0, 12)
        val cipherAndTag = payload.copyOfRange(12, payload.size)
        val cipher = Cipher.getInstance(transformation)
        if (keyAlg == "AES") cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, keyAlg), GCMParameterSpec(128, nonce))
        else cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, keyAlg), IvParameterSpec(nonce))
        return cipher.doFinal(cipherAndTag)
    }
}
