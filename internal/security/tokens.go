package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"auth/internal/domain"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims - содержимое access-токена.
//
// Контракт с другими сервисами: подпись RS256, sub - ID пользователя (ULID),
// exp обязателен. sid - ID сессии устройства: по нему этот сервис проверяет,
// не завершена ли сессия. Другие сервисы могут его игнорировать.
type AccessClaims struct {
	jwt.RegisteredClaims
	SessionID string `json:"sid"`
}

// TokenIssuer выпускает и проверяет access-токены
type TokenIssuer struct {
	key    *rsa.PrivateKey
	keyID  string
	issuer string
	ttl    time.Duration
}

func NewTokenIssuer(key *rsa.PrivateKey, issuer string, ttl time.Duration) (*TokenIssuer, error) {
	keyID, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &TokenIssuer{key: key, keyID: keyID, issuer: issuer, ttl: ttl}, nil
}

// LoadPrivateKey читает приватный RSA-ключ из PEM-файла (PKCS#1 или PKCS#8)
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("private key %s is too short: %d bits, need at least 2048", path, key.N.BitLen())
	}
	return key, nil
}

// KeyID - стабильный идентификатор ключа: начало SHA-256 от публичного ключа.
// Попадает в заголовок kid токена и в JWKS, чтобы проверяющая сторона выбрала нужный ключ
// при ротации, когда в JWKS временно опубликованы старый и новый ключи.
func KeyID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:12]), nil
}

// Issue выпускает access-токен для сессии. Возвращает токен и срок его действия.
func (t *TokenIssuer) Issue(userID, sessionID string, now time.Time) (string, time.Time, error) {
	expires := now.Add(t.ttl)
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
		SessionID: sessionID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = t.keyID

	signed, err := token.SignedString(t.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expires, nil
}

// Verify проверяет подпись, срок и издателя токена на момент now
func (t *TokenIssuer) Verify(tokenString string, now time.Time) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims,
		func(*jwt.Token) (any, error) { return &t.key.PublicKey, nil },
		// Фиксируем алгоритм: иначе возможна подмена на HS256 с публичным ключом в роли секрета
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(t.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil || claims.Subject == "" || claims.SessionID == "" {
		return nil, domain.ErrUnauthorized
	}
	return claims, nil
}

// TTL - время жизни access-токена
func (t *TokenIssuer) TTL() time.Duration { return t.ttl }

// JWK - открытый ключ в формате JSON Web Key (RFC 7517)
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	N         string `json:"n"`
	E         string `json:"e"`
}

// JWKS - набор публичных ключей для /.well-known/jwks.json.
// Другие сервисы берут ключ отсюда вместо копирования PEM-файла.
func (t *TokenIssuer) JWKS() map[string][]JWK {
	pub := t.key.PublicKey
	return map[string][]JWK{"keys": {{
		KeyType:   "RSA",
		Use:       "sig",
		Algorithm: jwt.SigningMethodRS256.Alg(),
		KeyID:     t.keyID,
		N:         base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// PublicKeyPEM - публичный ключ в PEM, для сервисов, которые читают ключ из файла
func (t *TokenIssuer) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&t.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// --- Refresh-токены ---

const (
	refreshPrefix = "rt_"
	refreshBytes  = 32
)

var errMalformedRefresh = errors.New("malformed refresh token")

// NewRefreshToken возвращает случайный refresh-токен и его хэш для хранения в БД.
// 256 бит случайности: перебор невозможен, поэтому хватает быстрого SHA-256 без соли.
func NewRefreshToken() (token string, hash []byte, err error) {
	raw := make([]byte, refreshBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	token = refreshPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashRefreshToken(token), nil
}

func HashRefreshToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// CheckRefreshFormat отсекает заведомо мусорные строки до похода в базу
func CheckRefreshFormat(token string) error {
	if len(token) != len(refreshPrefix)+base64.RawURLEncoding.EncodedLen(refreshBytes) ||
		token[:len(refreshPrefix)] != refreshPrefix {
		return errMalformedRefresh
	}
	return nil
}
