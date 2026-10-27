# Prueba SecretCrypto contra decrypt/test-vectors.txt. Uso: python SecretCryptoTest.py
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from SecretCrypto import SecretCryptoError, decrypt  # noqa: E402

ALGORITHMS = ["aes256gcm", "chacha20poly1305", "aes256cbc-hmac", "aes128gcm", "aes256cbc", "3des", "base64"]


def loadVectors():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-vectors.txt")
    vectors = {}
    with open(path, encoding="utf-8") as file:
        for line in file:
            line = line.rstrip("\n")
            if line and not line.startswith("#"):
                key, _, value = line.partition("=")
                vectors[key] = value
    return vectors


def expectError(action):
    try:
        action()
    except SecretCryptoError:
        return
    raise AssertionError("Se esperaba un error")


vec = loadVectors()
key, plain = vec["masterKey"], vec["plainText"]
for alg in ALGORITHMS:
    assert decrypt(vec[alg], key) == plain, alg
    assert decrypt(vec[alg + ".raw"], key, alg) == plain, alg + ".raw"
expectError(lambda: decrypt(vec["tampered"], key))
expectError(lambda: decrypt(vec["aes256gcm"], key, "aes128gcm"))
print(f"Python: {len(ALGORITHMS) * 2 + 2} pruebas correctas")
