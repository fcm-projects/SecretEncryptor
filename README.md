# SecretEncryptor

[![Pruebas de descifrado](https://github.com/fcm-projects/SecretEncryptor/actions/workflows/tests.yml/badge.svg)](https://github.com/fcm-projects/SecretEncryptor/actions/workflows/tests.yml)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue)

Herramienta de escritorio para cifrar contraseñas, tokens y otros secretos antes de publicarlos en un endpoint o en un archivo de configuración. La aplicación cliente los descifra con la librería `SecretCrypto`, disponible para **Python, Java, Kotlin, C#, JavaScript, Go, PHP, Ruby y Rust**.

## Funciones

- Cifrado con siete algoritmos, ordenados de más a menos seguro.
- Prefijo del algoritmo opcional en el valor cifrado.
- Verificación: descifra un valor para confirmar que corresponde a la llave antes de entregarlo.
- Generador de propuestas de llaves maestras (Base64, 256 bits) y de tokens de acceso (hexadecimal, 256 bits).
- El portapapeles se limpia a los 60 segundos y al cerrar la ventana.
- No guarda llaves ni valores en disco.
- Librerías de descifrado en nueve lenguajes, probadas automáticamente contra los mismos valores de referencia.

## Algoritmos

| Código | Algoritmo | Seguridad | Observación |
|---|---|---|---|
| `aes256gcm` | AES-256-GCM | Muy alta | Recomendado |
| `chacha20poly1305` | ChaCha20-Poly1305 | Muy alta | Android 9+ (API 28) |
| `aes256cbc-hmac` | AES-256-CBC + HMAC-SHA256 | Alta | Máxima compatibilidad |
| `aes128gcm` | AES-128-GCM | Alta | Llave de 128 bits |
| `aes256cbc` | AES-256-CBC sin autenticación | Media | No detecta alteraciones |
| `3des` | 3DES-CBC | Baja | Solo para sistemas antiguos |
| `base64` | Base64 | Nula | Codificación, no cifrado |

La llave de cada algoritmo se deriva de la llave maestra con HMAC-SHA256 y una etiqueta propia, de modo que la llave maestra nunca se usa directamente para cifrar.

## Formato del valor cifrado

El algoritmo puede viajar de dos formas:

| Opción | Valor | Cuándo usarla |
|---|---|---|
| Con prefijo | `aes256gcm:3q2+7w...` | El valor se guarda o se copia solo, por ejemplo en un archivo de configuración. |
| Sin prefijo | `3q2+7w...` | El algoritmo se indica por separado, por ejemplo en un campo `alg` de la respuesta de un endpoint. |

La casilla "Incluir prefijo del algoritmo" de la pestaña Cifrar elige entre las dos. Mostrar el algoritmo no debilita el cifrado: la seguridad depende solo de la llave maestra.

Estructura del contenido en Base64, por algoritmo:

| Algoritmo | Contenido | Llave derivada (etiqueta HMAC) |
|---|---|---|
| `aes256gcm` | nonce (12) + cifrado + tag (16) | `aes256gcm` |
| `chacha20poly1305` | nonce (12) + cifrado + tag (16) | `chacha20` |
| `aes256cbc-hmac` | IV (16) + cifrado + HMAC-SHA256 (32) | `enc` para cifrar, `mac` para el HMAC |
| `aes128gcm` | nonce (12) + cifrado + tag (16) | `aes128gcm`, primeros 16 bytes |
| `aes256cbc` | IV (16) + cifrado (PKCS#7) | `aes256cbc` |
| `3des` | IV (8) + cifrado (PKCS#7) | `3des`, primeros 24 bytes |

Con esta especificación, el valor puede descifrarse también en cualquier otro lenguaje que soporte estos algoritmos.

## Uso de la aplicación

```
pip install -r requirements.txt
python SecretEncryptor.py
```

En Windows, `ConstruirExe.bat` genera `dist\SecretEncryptor.exe` con PyInstaller. También puedes descargar el ejecutable desde la sección [Releases](https://github.com/fcm-projects/SecretEncryptor/releases).

## Descifrado en la aplicación cliente

Copia a tu proyecto el archivo del lenguaje que necesites desde la carpeta `decrypt/`. Todas las versiones exponen la misma función: el valor cifrado, la llave maestra y, si el valor no tiene prefijo, el algoritmo.

| Lenguaje | Archivo | Requisitos |
|---|---|---|
| Python | `decrypt/python/SecretCrypto.py` | Python 3.8+, `cryptography` 42+ |
| Java | `decrypt/java/SecretCrypto.java` | Java 11+ (ChaCha20-Poly1305) |
| Kotlin (Android) | `decrypt/kotlin/SecretCrypto.kt` | Android API 26+ (API 28 para ChaCha20) |
| C# | `decrypt/csharp/SecretCrypto.cs` | .NET 8+ |
| JavaScript | `decrypt/javascript/SecretCrypto.js` | Node.js 18+ |
| Go | `decrypt/go/secretcrypto.go` | Go 1.21+, `golang.org/x/crypto` |
| PHP | `decrypt/php/SecretCrypto.php` | PHP 8.0+, extensiones `openssl` y `sodium` |
| Ruby | `decrypt/ruby/secret_crypto.rb` | Ruby 3.0+, librería estándar |
| Rust | `decrypt/rust/` | Crates de RustCrypto (ver `Cargo.toml`) |

Ejemplos, primero con un valor con prefijo y luego sin prefijo:

**Python**

```python
from SecretCrypto import decrypt

secret = decrypt(value, masterKeyBase64)
secret = decrypt(value, masterKeyBase64, "aes256gcm")
```

**Java**

```java
String secret = SecretCrypto.decrypt(value, masterKeyBase64);
String secret = SecretCrypto.decrypt(value, masterKeyBase64, "aes256gcm");
```

**Kotlin (Android)**

```kotlin
val secret = SecretCrypto.decrypt(value, masterKeyBase64)
val secret = SecretCrypto.decrypt(value, masterKeyBase64, "aes256gcm")
```

**C#**

```csharp
string secret = SecretCrypto.Decrypt(value, masterKeyBase64);
string secret = SecretCrypto.Decrypt(value, masterKeyBase64, "aes256gcm");
```

**JavaScript (Node.js)**

```javascript
const { decrypt } = require('./SecretCrypto');

const secret = decrypt(value, masterKeyBase64);
const secret = decrypt(value, masterKeyBase64, 'aes256gcm');
```

**Go**

```go
secret, err := secretcrypto.Decrypt(value, masterKeyBase64, "")
secret, err := secretcrypto.Decrypt(value, masterKeyBase64, "aes256gcm")
```

**PHP**

```php
$secret = SecretCrypto::decrypt($value, $masterKeyBase64);
$secret = SecretCrypto::decrypt($value, $masterKeyBase64, 'aes256gcm');
```

**Ruby**

```ruby
secret = SecretCrypto.decrypt(value, master_key_base64)
secret = SecretCrypto.decrypt(value, master_key_base64, "aes256gcm")
```

**Rust**

```rust
let secret = secret_crypto::decrypt(&value, &master_key_base64, None)?;
let secret = secret_crypto::decrypt(&value, &master_key_base64, Some("aes256gcm"))?;
```

Ejemplo con un endpoint que responde `{"password": "3q2+7w...", "alg": "aes256gcm"}`:

```kotlin
val secret = SecretCrypto.decrypt(json.getString("password"), masterKeyBase64, json.getString("alg"))
```

## Pruebas

El archivo `decrypt/test-vectors.txt` contiene una llave y valores cifrados con la aplicación para los siete algoritmos, con y sin prefijo, además de un valor alterado que debe rechazarse. Cada lenguaje incluye una prueba que los descifra, y GitHub Actions las ejecuta en cada cambio (excepto Kotlin, que depende de Android).

| Lenguaje | Comando (desde su carpeta) |
|---|---|
| Python | `python SecretCryptoTest.py` |
| Java | `javac -d build SecretCrypto.java SecretCryptoTest.java && java -cp build SecretCryptoTest` |
| C# | `cd SecretCryptoTest && dotnet run` |
| JavaScript | `node SecretCryptoTest.js` |
| Go | `go test ./...` |
| PHP | `php SecretCryptoTest.php` |
| Ruby | `ruby secret_crypto_test.rb` |
| Rust | `cargo test` |

## Recomendaciones

- No incluyas la llave maestra como texto en el repositorio de la aplicación cliente. Inyéctala en la compilación o en variables de entorno y, en apps móviles, ofusca el código (por ejemplo, con R8 en Android).
- Comparte la llave maestra y el token por canales distintos y privados.
- Rota la llave, los tokens y los secretos cifrados cuando cambie el personal o el proveedor con acceso.

## Licencia

Distribuido bajo la licencia MIT. Consulta el archivo `LICENSE`.
