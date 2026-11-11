// Package security - пароли, access-токены и refresh-токены.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	saltLength = 16
	keyLength  = 32
)

var ErrMalformedHash = errors.New("malformed password hash")

// PasswordHasher хэширует пароли argon2id.
//
// Хэш хранится в формате PHC вместе с параметрами:
// $argon2id$v=19$m=19456,t=2,p=1$<соль>$<хэш>
// Поэтому параметры можно усилить позже: старые хэши проверятся со своими параметрами,
// а NeedsRehash подскажет, что хэш пора пересчитать при следующем входе.
type PasswordHasher struct {
	memory      uint32 // KiB
	iterations  uint32
	parallelism uint8
}

func NewPasswordHasher(memoryKiB, iterations uint32, parallelism uint8) *PasswordHasher {
	return &PasswordHasher{memory: memoryKiB, iterations: iterations, parallelism: parallelism}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, keyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.iterations, h.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify сравнивает пароль с хэшем за постоянное время
func (h *PasswordHasher) Verify(password, encoded string) (bool, error) {
	p, err := parseHash(encoded)
	if err != nil {
		return false, err
	}

	key := argon2.IDKey([]byte(password), p.salt, p.iterations, p.memory, p.parallelism, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

// NeedsRehash сообщает, что хэш посчитан со старыми параметрами
func (h *PasswordHasher) NeedsRehash(encoded string) bool {
	p, err := parseHash(encoded)
	if err != nil {
		return true
	}
	return p.memory != h.memory || p.iterations != h.iterations || p.parallelism != h.parallelism
}

type hashParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func parseHash(encoded string) (*hashParams, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, ErrMalformedHash
	}

	var p hashParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); err != nil {
		return nil, ErrMalformedHash
	}

	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, ErrMalformedHash
	}
	if p.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(p.key) == 0 {
		return nil, ErrMalformedHash
	}
	return &p, nil
}
