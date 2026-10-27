// Prueba SecretCrypto contra decrypt/test-vectors.txt. Uso: node SecretCryptoTest.js
'use strict';
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { decrypt } = require('./SecretCrypto');

const ALGORITHMS = ['aes256gcm', 'chacha20poly1305', 'aes256cbc-hmac', 'aes128gcm', 'aes256cbc', '3des', 'base64'];

const vec = {};
for (const line of fs.readFileSync(path.join(__dirname, '..', 'test-vectors.txt'), 'utf8').split('\n')) {
  if (!line || line.startsWith('#')) continue;
  const i = line.indexOf('=');
  vec[line.substring(0, i)] = line.substring(i + 1);
}

const key = vec.masterKey;
const plain = vec.plainText;
for (const alg of ALGORITHMS) {
  assert.strictEqual(decrypt(vec[alg], key), plain, alg);
  assert.strictEqual(decrypt(vec[`${alg}.raw`], key, alg), plain, `${alg}.raw`);
}
assert.throws(() => decrypt(vec.tampered, key));
assert.throws(() => decrypt(vec.aes256gcm, key, 'aes128gcm'));
console.log(`JavaScript: ${ALGORITHMS.length * 2 + 2} pruebas correctas`);
