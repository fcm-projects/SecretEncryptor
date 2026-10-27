// Package secretcrypto descifra los valores generados con SecretEncryptor (Go).
//
// Formato del valor:
//
//	con prefijo:  "<algoritmo>:<Base64>"  -> secretcrypto.Decrypt(valor, llave, "")
//	sin prefijo:  "<Base64>"              -> secretcrypto.Decrypt(valor, llave, "aes256gcm")
//
// Algoritmos: aes256gcm, chacha20poly1305, aes256cbc-hmac, aes128gcm,
// aes256cbc, 3des, base64 (sin llave).
package secretcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Decrypt descifra un valor. Si trae prefijo, algorithm puede ir vacío; si se indican ambos, deben coincidir.
func Decrypt(value, masterKeyBase64, algorithm string) (string, error) {
	v := strings.TrimSpace(value)
	body := v
	if sep := strings.Index(v, ":"); sep > 0 {
		prefix := v[:sep]
		if algorithm != "" && algorithm != prefix {
			return "", fmt.Errorf("el prefijo (%s) no coincide con el algoritmo indicado (%s)", prefix, algorithm)
		}
		algorithm = prefix
		body = v[sep+1:]
	}
	if algorithm == "" {
		return "", errors.New("el valor no tiene prefijo: indica el algoritmo")
	}

	payload, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("base64 inválido: %w", err)
	}
	if algorithm == "base64" {
		return string(payload), nil
	}

	mk, err := parseMasterKey(masterKeyBase64)
	if err != nil {
		return "", err
	}

	var data []byte
	switch algorithm {
	case "aes256gcm":
		data, err = aesGcm(deriveKey(mk, "aes256gcm"), payload)
	case "chacha20poly1305":
		var aead cipher.AEAD
		if aead, err = chacha20poly1305.New(deriveKey(mk, "chacha20")); err == nil {
			data, err = openAead(aead, payload)
		}
	case "aes128gcm":
		data, err = aesGcm(deriveKey(mk, "aes128gcm")[:16], payload)
	case "aes256cbc-hmac":
		if len(payload) < 32 {
			return "", errors.New("valor cifrado demasiado corto")
		}
		ivct, tag := payload[:len(payload)-32], payload[len(payload)-32:]
		mac := hmac.New(sha256.New, deriveKey(mk, "mac"))
		mac.Write(ivct)
		if !hmac.Equal(mac.Sum(nil), tag) {
			return "", errors.New("integridad no válida")
		}
		var block cipher.Block
		if block, err = aes.NewCipher(deriveKey(mk, "enc")); err == nil {
			data, err = cbc(block, ivct)
		}
	case "aes256cbc":
		var block cipher.Block
		if block, err = aes.NewCipher(deriveKey(mk, "aes256cbc")); err == nil {
			data, err = cbc(block, payload)
		}
	case "3des":
		var block cipher.Block
		if block, err = des.NewTripleDESCipher(deriveKey(mk, "3des")[:24]); err == nil {
			data, err = cbc(block, payload)
		}
	default:
		return "", fmt.Errorf("algoritmo no soportado: %s", algorithm)
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func deriveKey(masterKey []byte, label string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

func parseMasterKey(masterKeyBase64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(masterKeyBase64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("llave maestra inválida: debe tener 32 bytes en Base64")
	}
	return key, nil
}

func aesGcm(key, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return openAead(aead, payload)
}

func openAead(aead cipher.AEAD, payload []byte) ([]byte, error) {
	if len(payload) < 12+16 {
		return nil, errors.New("valor cifrado demasiado corto")
	}
	data, err := aead.Open(nil, payload[:12], payload[12:], nil)
	if err != nil {
		return nil, errors.New("no se pudo descifrar: la llave o el algoritmo no corresponden")
	}
	return data, nil
}

func cbc(block cipher.Block, payload []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(payload) < 2*size || len(payload)%size != 0 {
		return nil, errors.New("longitud del valor cifrado inválida")
	}
	data := make([]byte, len(payload)-size)
	cipher.NewCBCDecrypter(block, payload[:size]).CryptBlocks(data, payload[size:])
	pad := int(data[len(data)-1])
	if pad == 0 || pad > size {
		return nil, errors.New("relleno inválido: la llave o el algoritmo no corresponden")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("relleno inválido: la llave o el algoritmo no corresponden")
		}
	}
	return data[:len(data)-pad], nil
}
