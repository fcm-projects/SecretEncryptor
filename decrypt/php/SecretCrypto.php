<?php
// SecretCrypto - Descifra los valores generados con SecretEncryptor (PHP 8.0 o superior).
//
// Formato del valor:
//   con prefijo:  "<algoritmo>:<Base64>"  -> SecretCrypto::decrypt($valor, $llave)
//   sin prefijo:  "<Base64>"              -> SecretCrypto::decrypt($valor, $llave, 'aes256gcm')
//
// Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
//             aes256cbc, 3des, base64 (sin llave).
//
// Requiere las extensiones openssl y sodium (incluidas por defecto desde PHP 7.2).

final class SecretCrypto
{
    /**
     * Descifra un valor. Si trae prefijo, el algoritmo es opcional; si se indican ambos, deben coincidir.
     */
    public static function decrypt(string $value, string $masterKeyBase64, ?string $algorithm = null): string
    {
        $v = trim($value);
        $body = $v;
        $sep = strpos($v, ':');
        if ($sep !== false && $sep > 0) {
            $prefix = substr($v, 0, $sep);
            if ($algorithm !== null && $algorithm !== $prefix) {
                throw new InvalidArgumentException("El prefijo ($prefix) no coincide con el algoritmo indicado ($algorithm)");
            }
            $algorithm = $prefix;
            $body = substr($v, $sep + 1);
        }
        if ($algorithm === null) {
            throw new InvalidArgumentException('El valor no tiene prefijo: indica el algoritmo');
        }

        $payload = base64_decode($body, true);
        if ($payload === false) {
            throw new InvalidArgumentException('Base64 inválido');
        }
        if ($algorithm === 'base64') {
            return $payload;
        }

        $mk = self::parseMasterKey($masterKeyBase64);
        switch ($algorithm) {
            case 'aes256gcm':
                $data = self::aesGcm('aes-256-gcm', self::deriveKey($mk, 'aes256gcm'), $payload);
                break;
            case 'chacha20poly1305':
                $data = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
                    substr($payload, 12), '', substr($payload, 0, 12), self::deriveKey($mk, 'chacha20'));
                break;
            case 'aes128gcm':
                $data = self::aesGcm('aes-128-gcm', substr(self::deriveKey($mk, 'aes128gcm'), 0, 16), $payload);
                break;
            case 'aes256cbc-hmac':
                $ivct = substr($payload, 0, -32);
                $tag = substr($payload, -32);
                if (!hash_equals(hash_hmac('sha256', $ivct, self::deriveKey($mk, 'mac'), true), $tag)) {
                    throw new RuntimeException('Integridad no válida');
                }
                $data = self::cbc('aes-256-cbc', self::deriveKey($mk, 'enc'), 16, $ivct);
                break;
            case 'aes256cbc':
                $data = self::cbc('aes-256-cbc', self::deriveKey($mk, 'aes256cbc'), 16, $payload);
                break;
            case '3des':
                $data = self::cbc('des-ede3-cbc', substr(self::deriveKey($mk, '3des'), 0, 24), 8, $payload);
                break;
            default:
                throw new InvalidArgumentException("Algoritmo no soportado: $algorithm");
        }
        if ($data === false) {
            throw new RuntimeException('No se pudo descifrar: la llave o el algoritmo no corresponden');
        }
        return $data;
    }

    private static function deriveKey(string $masterKey, string $label): string
    {
        return hash_hmac('sha256', $label, $masterKey, true);
    }

    private static function parseMasterKey(string $masterKeyBase64): string
    {
        $key = base64_decode(trim($masterKeyBase64), true);
        if ($key === false || strlen($key) !== 32) {
            throw new InvalidArgumentException('Llave maestra inválida: debe tener 32 bytes');
        }
        return $key;
    }

    /** @return string|false */
    private static function aesGcm(string $cipher, string $key, string $payload)
    {
        return openssl_decrypt(substr($payload, 12, -16), $cipher, $key, OPENSSL_RAW_DATA,
            substr($payload, 0, 12), substr($payload, -16));
    }

    /** @return string|false */
    private static function cbc(string $cipher, string $key, int $ivSize, string $payload)
    {
        return openssl_decrypt(substr($payload, $ivSize), $cipher, $key, OPENSSL_RAW_DATA, substr($payload, 0, $ivSize));
    }
}
