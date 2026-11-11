// keygen создает пару RSA-ключей для подписи access-токенов.
//
//	go run ./cmd/keygen               # keys/jwt_private.pem и keys/jwt_public.pem
//	go run ./cmd/keygen -dir secrets  # в другой каталог
//
// Приватный ключ остается у сервиса авторизации. Публичный ключ раздается сервисам,
// которые проверяют токены (или они берут его из /.well-known/jwks.json).
// Существующие ключи не перезаписываются.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func main() {
	dir := flag.String("dir", "keys", "каталог для ключей")
	bits := flag.Int("bits", 2048, "длина ключа")
	flag.Parse()

	if err := run(*dir, *bits); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir string, bits int) error {
	privatePath := filepath.Join(dir, "jwt_private.pem")
	publicPath := filepath.Join(dir, "jwt_public.pem")

	if _, err := os.Stat(privatePath); err == nil {
		return fmt.Errorf("%s already exists, remove it first to generate a new key", privatePath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		return err
	}

	fmt.Println("private key:", privatePath)
	fmt.Println("public key: ", publicPath)
	return nil
}
