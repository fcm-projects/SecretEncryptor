// SecretCrypto - Descifra los valores generados con SecretEncryptor (C#, .NET 8 o superior).
//
// Formato del valor:
//   con prefijo:  "<algoritmo>:<Base64>"  -> SecretCrypto.Decrypt(valor, llave)
//   sin prefijo:  "<Base64>"              -> SecretCrypto.Decrypt(valor, llave, "aes256gcm")
//
// Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
//             aes256cbc, 3des, base64 (sin llave).
//
// ChaCha20-Poly1305 requiere soporte del sistema operativo (Windows 10+, Linux con OpenSSL 1.1+).
// Solo usa System.Security.Cryptography.
using System;
using System.Security.Cryptography;
using System.Text;

public static class SecretCrypto
{
    /// <summary>
    /// Descifra un valor. Si trae prefijo, el algoritmo es opcional; si se indican ambos, deben coincidir.
    /// </summary>
    public static string Decrypt(string value, string masterKeyBase64, string? algorithm = null)
    {
        string v = value.Trim();
        string body = v;
        int sep = v.IndexOf(':');
        if (sep > 0)
        {
            string prefix = v.Substring(0, sep);
            if (algorithm != null && algorithm != prefix)
                throw new ArgumentException($"El prefijo ({prefix}) no coincide con el algoritmo indicado ({algorithm})");
            algorithm = prefix;
            body = v.Substring(sep + 1);
        }
        if (algorithm == null) throw new ArgumentException("El valor no tiene prefijo: indica el algoritmo");

        byte[] payload = Convert.FromBase64String(body);
        if (algorithm == "base64") return Encoding.UTF8.GetString(payload);

        byte[] mk = ParseMasterKey(masterKeyBase64);
        byte[] data;
        switch (algorithm)
        {
            case "aes256gcm":
                data = AesGcmDecrypt(DeriveKey(mk, "aes256gcm"), payload);
                break;
            case "chacha20poly1305":
                data = ChaChaDecrypt(DeriveKey(mk, "chacha20"), payload);
                break;
            case "aes128gcm":
                data = AesGcmDecrypt(DeriveKey(mk, "aes128gcm")[..16], payload);
                break;
            case "aes256cbc-hmac":
            {
                byte[] ivct = payload[..^32];
                byte[] tag = payload[^32..];
                byte[] expected = HMACSHA256.HashData(DeriveKey(mk, "mac"), ivct);
                if (!CryptographicOperations.FixedTimeEquals(expected, tag))
                    throw new CryptographicException("Integridad no válida");
                using Aes aes = Aes.Create();
                aes.Key = DeriveKey(mk, "enc");
                data = aes.DecryptCbc(ivct[16..], ivct[..16], PaddingMode.PKCS7);
                break;
            }
            case "aes256cbc":
            {
                using Aes aes = Aes.Create();
                aes.Key = DeriveKey(mk, "aes256cbc");
                data = aes.DecryptCbc(payload[16..], payload[..16], PaddingMode.PKCS7);
                break;
            }
            case "3des":
            {
                using TripleDES des = TripleDES.Create();
                des.Key = DeriveKey(mk, "3des")[..24];
                data = des.DecryptCbc(payload[8..], payload[..8], PaddingMode.PKCS7);
                break;
            }
            default:
                throw new ArgumentException($"Algoritmo no soportado: {algorithm}");
        }
        return Encoding.UTF8.GetString(data);
    }

    private static byte[] DeriveKey(byte[] masterKey, string label) =>
        HMACSHA256.HashData(masterKey, Encoding.UTF8.GetBytes(label));

    private static byte[] ParseMasterKey(string masterKeyBase64)
    {
        byte[] key = Convert.FromBase64String(masterKeyBase64.Trim());
        if (key.Length != 32) throw new ArgumentException("Llave maestra inválida: debe tener 32 bytes");
        return key;
    }

    private static byte[] AesGcmDecrypt(byte[] key, byte[] payload)
    {
        byte[] plain = new byte[payload.Length - 28];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(payload[..12], payload[12..^16], payload[^16..], plain);
        return plain;
    }

    private static byte[] ChaChaDecrypt(byte[] key, byte[] payload)
    {
        byte[] plain = new byte[payload.Length - 28];
        using var chacha = new ChaCha20Poly1305(key);
        chacha.Decrypt(payload[..12], payload[12..^16], payload[^16..], plain);
        return plain;
    }
}
