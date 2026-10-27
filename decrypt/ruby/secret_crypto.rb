# SecretCrypto - Descifra los valores generados con SecretEncryptor (Ruby 3.0 o superior).
#
# Formato del valor:
#   con prefijo:  "<algoritmo>:<Base64>"  -> SecretCrypto.decrypt(valor, llave)
#   sin prefijo:  "<Base64>"              -> SecretCrypto.decrypt(valor, llave, "aes256gcm")
#
# Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
#             aes256cbc, 3des, base64 (sin llave).
#
# Solo usa la librería estándar (openssl y base64).
require "base64"
require "openssl"

module SecretCrypto
  class Error < StandardError; end

  module_function

  # Descifra un valor. Si trae prefijo, el algoritmo es opcional; si se indican ambos, deben coincidir.
  def decrypt(value, master_key_base64, algorithm = nil)
    v = value.strip
    body = v
    sep = v.index(":")
    if sep && sep.positive?
      prefix = v[0...sep]
      if algorithm && algorithm != prefix
        raise Error, "El prefijo (#{prefix}) no coincide con el algoritmo indicado (#{algorithm})"
      end
      algorithm = prefix
      body = v[(sep + 1)..]
    end
    raise Error, "El valor no tiene prefijo: indica el algoritmo" unless algorithm

    payload = Base64.strict_decode64(body)
    return payload.force_encoding(Encoding::UTF_8) if algorithm == "base64"

    mk = parse_master_key(master_key_base64)
    data =
      case algorithm
      when "aes256gcm" then aead("aes-256-gcm", derive_key(mk, "aes256gcm"), payload)
      when "chacha20poly1305" then aead("chacha20-poly1305", derive_key(mk, "chacha20"), payload)
      when "aes128gcm" then aead("aes-128-gcm", derive_key(mk, "aes128gcm")[0, 16], payload)
      when "aes256cbc-hmac"
        ivct = payload[0...-32]
        tag = payload[-32..]
        expected = OpenSSL::HMAC.digest("SHA256", derive_key(mk, "mac"), ivct)
        raise Error, "Integridad no válida" unless OpenSSL.fixed_length_secure_compare(expected, tag)

        cbc("aes-256-cbc", derive_key(mk, "enc"), 16, ivct)
      when "aes256cbc" then cbc("aes-256-cbc", derive_key(mk, "aes256cbc"), 16, payload)
      when "3des" then cbc("des-ede3-cbc", derive_key(mk, "3des")[0, 24], 8, payload)
      else raise Error, "Algoritmo no soportado: #{algorithm}"
      end
    data.force_encoding(Encoding::UTF_8)
  rescue OpenSSL::Cipher::CipherError, ArgumentError => e
    raise Error, "No se pudo descifrar: la llave o el algoritmo no corresponden (#{e.message})"
  end

  def derive_key(master_key, label)
    OpenSSL::HMAC.digest("SHA256", master_key, label)
  end

  def parse_master_key(master_key_base64)
    key = Base64.strict_decode64(master_key_base64.strip)
    raise Error, "Llave maestra inválida: debe tener 32 bytes" unless key.bytesize == 32

    key
  end

  def aead(cipher_name, key, payload)
    cipher = OpenSSL::Cipher.new(cipher_name).decrypt
    cipher.key = key
    cipher.iv = payload[0, 12]
    cipher.auth_tag = payload[-16..]
    cipher.auth_data = ""
    cipher.update(payload[12...-16]) + cipher.final
  end

  def cbc(cipher_name, key, iv_size, payload)
    cipher = OpenSSL::Cipher.new(cipher_name).decrypt
    cipher.key = key
    cipher.iv = payload[0, iv_size]
    cipher.update(payload[iv_size..]) + cipher.final
  end

  private_class_method :derive_key, :parse_master_key, :aead, :cbc
end
