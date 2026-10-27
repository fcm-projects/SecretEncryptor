// Prueba SecretCrypto contra decrypt/test-vectors.txt. Uso: dotnet run
using System;
using System.Collections.Generic;
using System.IO;

string[] algorithms = { "aes256gcm", "chacha20poly1305", "aes256cbc-hmac", "aes128gcm", "aes256cbc", "3des", "base64" };

var vec = new Dictionary<string, string>();
string vectorsPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "test-vectors.txt");
foreach (string line in File.ReadAllLines(vectorsPath))
{
    if (line.Length == 0 || line.StartsWith('#')) continue;
    int i = line.IndexOf('=');
    vec[line[..i]] = line[(i + 1)..];
}

string key = vec["masterKey"];
string plain = vec["plainText"];
foreach (string alg in algorithms)
{
    Check(SecretCrypto.Decrypt(vec[alg], key) == plain, alg);
    Check(SecretCrypto.Decrypt(vec[alg + ".raw"], key, alg) == plain, alg + ".raw");
}
ExpectError(() => SecretCrypto.Decrypt(vec["tampered"], key));
ExpectError(() => SecretCrypto.Decrypt(vec["aes256gcm"], key, "aes128gcm"));
Console.WriteLine($"C#: {algorithms.Length * 2 + 2} pruebas correctas");

static void Check(bool ok, string name)
{
    if (!ok) throw new Exception("Falló: " + name);
}

static void ExpectError(Action action)
{
    try { action(); } catch (Exception) { return; }
    throw new Exception("Se esperaba un error");
}
