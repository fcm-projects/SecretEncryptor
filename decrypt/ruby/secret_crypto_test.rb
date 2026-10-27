# Prueba SecretCrypto contra decrypt/test-vectors.txt. Uso: ruby secret_crypto_test.rb
require_relative "secret_crypto"

ALGORITHMS = %w[aes256gcm chacha20poly1305 aes256cbc-hmac aes128gcm aes256cbc 3des base64].freeze

vec = {}
File.readlines(File.join(__dir__, "..", "test-vectors.txt"), chomp: true, encoding: "UTF-8").each do |line|
  next if line.empty? || line.start_with?("#")

  key, value = line.split("=", 2)
  vec[key] = value
end

def check(ok, name)
  abort "Falló: #{name}" unless ok
end

def expect_error(name)
  yield
  abort "Se esperaba un error: #{name}"
rescue SecretCrypto::Error
  nil
end

key = vec["masterKey"]
plain = vec["plainText"]
ALGORITHMS.each do |alg|
  check(SecretCrypto.decrypt(vec[alg], key) == plain, alg)
  check(SecretCrypto.decrypt(vec["#{alg}.raw"], key, alg) == plain, "#{alg}.raw")
end
expect_error("tampered") { SecretCrypto.decrypt(vec["tampered"], key) }
expect_error("mismatch") { SecretCrypto.decrypt(vec["aes256gcm"], key, "aes128gcm") }
puts "Ruby: #{ALGORITHMS.size * 2 + 2} pruebas correctas"
