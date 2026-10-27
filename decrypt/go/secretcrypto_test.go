package secretcrypto

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

var algorithms = []string{"aes256gcm", "chacha20poly1305", "aes256cbc-hmac", "aes128gcm", "aes256cbc", "3des", "base64"}

func loadVectors(t *testing.T) map[string]string {
	file, err := os.Open("../test-vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	vec := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		vec[key] = value
	}
	return vec
}

func TestVectors(t *testing.T) {
	vec := loadVectors(t)
	key, plain := vec["masterKey"], vec["plainText"]
	for _, alg := range algorithms {
		if got, err := Decrypt(vec[alg], key, ""); err != nil || got != plain {
			t.Errorf("%s: %q %v", alg, got, err)
		}
		if got, err := Decrypt(vec[alg+".raw"], key, alg); err != nil || got != plain {
			t.Errorf("%s.raw: %q %v", alg, got, err)
		}
	}
	if _, err := Decrypt(vec["tampered"], key, ""); err == nil {
		t.Error("se esperaba un error con el valor alterado")
	}
	if _, err := Decrypt(vec["aes256gcm"], key, "aes128gcm"); err == nil {
		t.Error("se esperaba un error con el algoritmo distinto al prefijo")
	}
}
