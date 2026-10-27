# SecretCrypto - Descifra los valores generados con SecretEncryptor (Python).
#
# Formato del valor:
#   con prefijo:  "<algoritmo>:<Base64>"  -> decrypt(valor, llave)
#   sin prefijo:  "<Base64>"              -> decrypt(valor, llave, "aes256gcm")
#
# Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
#             aes256cbc, 3des, base64 (sin llave).
#
# Requiere: pip install "cryptography>=42"
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43
    TripleDES = algorithms.TripleDES

__all__ = ["decrypt", "SecretCryptoError"]

ALGORITHMS = ("aes256gcm", "chacha20poly1305", "aes256cbc-hmac", "aes128gcm", "aes256cbc", "3des", "base64")


class SecretCryptoError(ValueError):
    """Error al descifrar: formato, llave, algoritmo o integridad no válidos."""


def decrypt(value: str, masterKeyBase64: str, algorithm: str = None) -> str:
    """Descifra un valor. Si trae prefijo, el algoritmo es opcional; si se indican ambos, deben coincidir."""
    v = value.strip()
    body = v
    prefix, sep, rest = v.partition(":")
    if sep and prefix:
        if algorithm and algorithm != prefix:
            raise SecretCryptoError(f"El prefijo ({prefix}) no coincide con el algoritmo indicado ({algorithm})")
        algorithm, body = prefix, rest
    if not algorithm:
        raise SecretCryptoError("El valor no tiene prefijo: indica el algoritmo")
    if algorithm not in ALGORITHMS:
        raise SecretCryptoError(f"Algoritmo no soportado: {algorithm}")

    payload = base64.b64decode(body, validate=True)
    if algorithm == "base64":
        return payload.decode("utf-8")

    mk = _parseMasterKey(masterKeyBase64)
    try:
        if algorithm == "aes256gcm":
            data = AESGCM(_deriveKey(mk, "aes256gcm")).decrypt(payload[:12], payload[12:], None)
        elif algorithm == "chacha20poly1305":
            data = ChaCha20Poly1305(_deriveKey(mk, "chacha20")).decrypt(payload[:12], payload[12:], None)
        elif algorithm == "aes128gcm":
            data = AESGCM(_deriveKey(mk, "aes128gcm")[:16]).decrypt(payload[:12], payload[12:], None)
        elif algorithm == "aes256cbc-hmac":
            ivct, tag = payload[:-32], payload[-32:]
            expected = hmac.new(_deriveKey(mk, "mac"), ivct, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, tag):
                raise SecretCryptoError("Integridad no válida")
            data = _cbc(algorithms.AES, _deriveKey(mk, "enc"), 16, ivct)
        elif algorithm == "aes256cbc":
            data = _cbc(algorithms.AES, _deriveKey(mk, "aes256cbc"), 16, payload)
        else:  # 3des
            data = _cbc(TripleDES, _deriveKey(mk, "3des")[:24], 8, payload)
    except SecretCryptoError:
        raise
    except Exception as ex:
        raise SecretCryptoError("No se pudo descifrar: la llave o el algoritmo no corresponden") from ex
    return data.decode("utf-8")


def _deriveKey(masterKey: bytes, label: str) -> bytes:
    return hmac.new(masterKey, label.encode("utf-8"), hashlib.sha256).digest()


def _parseMasterKey(masterKeyBase64: str) -> bytes:
    key = base64.b64decode(masterKeyBase64.strip(), validate=True)
    if len(key) != 32:
        raise SecretCryptoError("Llave maestra inválida: debe tener 32 bytes")
    return key


def _cbc(algo, key: bytes, ivSize: int, payload: bytes) -> bytes:
    decryptor = Cipher(algo(key), modes.CBC(payload[:ivSize])).decryptor()
    padded = decryptor.update(payload[ivSize:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algo.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
