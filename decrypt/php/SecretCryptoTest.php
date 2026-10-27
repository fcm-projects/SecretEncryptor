<?php
// Prueba SecretCrypto contra decrypt/test-vectors.txt. Uso: php SecretCryptoTest.php
require __DIR__ . '/SecretCrypto.php';

$algorithms = ['aes256gcm', 'chacha20poly1305', 'aes256cbc-hmac', 'aes128gcm', 'aes256cbc', '3des', 'base64'];

$vec = [];
foreach (file(__DIR__ . '/../test-vectors.txt', FILE_IGNORE_NEW_LINES) as $line) {
    if ($line === '' || $line[0] === '#') {
        continue;
    }
    [$k, $v] = explode('=', $line, 2);
    $vec[$k] = $v;
}

function check(bool $ok, string $name): void
{
    if (!$ok) {
        fwrite(STDERR, "Falló: $name\n");
        exit(1);
    }
}

function expectError(callable $action, string $name): void
{
    try {
        $action();
    } catch (Throwable $e) {
        return;
    }
    check(false, $name);
}

$key = $vec['masterKey'];
$plain = $vec['plainText'];
foreach ($algorithms as $alg) {
    check(SecretCrypto::decrypt($vec[$alg], $key) === $plain, $alg);
    check(SecretCrypto::decrypt($vec["$alg.raw"], $key, $alg) === $plain, "$alg.raw");
}
expectError(fn () => SecretCrypto::decrypt($vec['tampered'], $key), 'tampered');
expectError(fn () => SecretCrypto::decrypt($vec['aes256gcm'], $key, 'aes128gcm'), 'mismatch');
echo 'PHP: ' . (count($algorithms) * 2 + 2) . " pruebas correctas\n";
