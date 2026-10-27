// SecretCrypto - Descifra los valores generados con SecretEncryptor (JavaScript, Node.js).
//
// Formato del valor:
//   con prefijo:  "<algoritmo>:<Base64>"  -> decrypt(valor, llave)
//   sin prefijo:  "<Base64>"              -> decrypt(valor, llave, "aes256gcm")
//
// Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
//             aes256cbc, 3des, base64 (sin llave).
//
// Requiere Node.js 18 o superior. Solo usa el módulo nativo "crypto".
'use strict';

const crypto = require('crypto');

const ALGORITHMS = ['aes256gcm', 'chacha20poly1305', 'aes256cbc-hmac', 'aes128gcm', 'aes256cbc', '3des', 'base64'];

/**
 * Descifra un valor. Si trae prefijo, el algoritmo es opcional; si se indican ambos, deben coincidir.
 * @param {string} value Valor cifrado.
 * @param {string} masterKeyBase64 Llave maestra en Base64 (32 bytes).
 * @param {string} [algorithm] Algoritmo, obligatorio si el valor no tiene prefijo.
 * @returns {string} Texto original.
 */
function decrypt(value, masterKeyBase64, algorithm) {
  const v = value.trim();
  let body = v;
  const sep = v.indexOf(':');
  if (sep > 0) {
    const prefix = v.substring(0, sep);
    if (algorithm && algorithm !== prefix) {
      throw new Error(`El prefijo (${prefix}) no coincide con el algoritmo indicado (${algorithm})`);
    }
    algorithm = prefix;
    body = v.substring(sep + 1);
  }
  if (!algorithm) throw new Error('El valor no tiene prefijo: indica el algoritmo');
  if (!ALGORITHMS.includes(algorithm)) throw new Error(`Algoritmo no soportado: ${algorithm}`);

  const payload = Buffer.from(body, 'base64');
  if (algorithm === 'base64') return payload.toString('utf8');

  const mk = parseMasterKey(masterKeyBase64);
  let data;
  switch (algorithm) {
    case 'aes256gcm':
      data = aead('aes-256-gcm', deriveKey(mk, 'aes256gcm'), payload);
      break;
    case 'chacha20poly1305':
      data = aead('chacha20-poly1305', deriveKey(mk, 'chacha20'), payload);
      break;
    case 'aes128gcm':
      data = aead('aes-128-gcm', deriveKey(mk, 'aes128gcm').subarray(0, 16), payload);
      break;
    case 'aes256cbc-hmac': {
      const ivct = payload.subarray(0, payload.length - 32);
      const tag = payload.subarray(payload.length - 32);
      const expected = crypto.createHmac('sha256', deriveKey(mk, 'mac')).update(ivct).digest();
      if (tag.length !== 32 || !crypto.timingSafeEqual(expected, tag)) throw new Error('Integridad no válida');
      data = cbc('aes-256-cbc', deriveKey(mk, 'enc'), 16, ivct);
      break;
    }
    case 'aes256cbc':
      data = cbc('aes-256-cbc', deriveKey(mk, 'aes256cbc'), 16, payload);
      break;
    case '3des':
      data = cbc('des-ede3-cbc', deriveKey(mk, '3des').subarray(0, 24), 8, payload);
      break;
  }
  return data.toString('utf8');
}

function deriveKey(masterKey, label) {
  return crypto.createHmac('sha256', masterKey).update(label, 'utf8').digest();
}

function parseMasterKey(masterKeyBase64) {
  const key = Buffer.from(masterKeyBase64.trim(), 'base64');
  if (key.length !== 32) throw new Error('Llave maestra inválida: debe tener 32 bytes');
  return key;
}

function aead(cipherName, key, payload) {
  const nonce = payload.subarray(0, 12);
  const tag = payload.subarray(payload.length - 16);
  const cipherText = payload.subarray(12, payload.length - 16);
  const decipher = crypto.createDecipheriv(cipherName, key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(cipherText), decipher.final()]);
}

function cbc(cipherName, key, ivSize, payload) {
  const decipher = crypto.createDecipheriv(cipherName, key, payload.subarray(0, ivSize));
  return Buffer.concat([decipher.update(payload.subarray(ivSize)), decipher.final()]);
}

module.exports = { decrypt };
