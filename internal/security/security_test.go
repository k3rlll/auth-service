package security_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"auth/internal/domain"
	"auth/internal/security"

	"github.com/golang-jwt/jwt/v5"
)

func TestPasswordHasher(t *testing.T) {
	h := security.NewPasswordHasher(64, 1, 1) // слабые параметры: тестам важна логика, не стойкость

	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}

	if ok, err := h.Verify("correct horse battery staple", hash); err != nil || !ok {
		t.Fatalf("correct password: ok=%v err=%v", ok, err)
	}
	if ok, _ := h.Verify("wrong password", hash); ok {
		t.Fatal("wrong password must not verify")
	}

	other, _ := h.Hash("correct horse battery staple")
	if other == hash {
		t.Fatal("hashes of the same password must differ (random salt)")
	}

	// Хэш с другими параметрами проверяется по своим параметрам
	stronger := security.NewPasswordHasher(128, 2, 1)
	if ok, _ := stronger.Verify("correct horse battery staple", hash); !ok {
		t.Fatal("old hash must verify with its own parameters")
	}
	if !stronger.NeedsRehash(hash) || h.NeedsRehash(hash) {
		t.Fatal("NeedsRehash must detect changed parameters")
	}

	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=x$a$b"} {
		if _, err := h.Verify("x", bad); !errors.Is(err, security.ErrMalformedHash) {
			t.Errorf("Verify(%q): err = %v, want ErrMalformedHash", bad, err)
		}
	}
}

func newIssuer(t *testing.T, ttl time.Duration) (*security.TokenIssuer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := security.NewTokenIssuer(key, "auth-service", ttl)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, key
}

func TestAccessTokens(t *testing.T) {
	issuer, key := newIssuer(t, 15*time.Minute)
	now := time.Now()

	token, expires, err := issuer.Issue("01JD8X3Q5N7ZK2W4M6R8T0V9YA", "session-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expires = %v", expires)
	}

	claims, err := issuer.Verify(token, now)
	if err != nil || claims.Subject != "01JD8X3Q5N7ZK2W4M6R8T0V9YA" || claims.SessionID != "session-1" {
		t.Fatalf("verify: %+v %v", claims, err)
	}

	// Заголовок kid совпадает с ключом в JWKS
	parsed, _, _ := jwt.NewParser().ParseUnverified(token, &security.AccessClaims{})
	jwks := issuer.JWKS()["keys"]
	if len(jwks) != 1 || parsed.Header["kid"] != jwks[0].KeyID || jwks[0].Algorithm != "RS256" {
		t.Fatalf("kid %v does not match JWKS %+v", parsed.Header["kid"], jwks)
	}

	otherIssuer, _ := newIssuer(t, time.Minute)
	foreign, _, _ := otherIssuer.Issue("u", "s", now)
	expired, _, _ := issuer.Issue("u", "s", now.Add(-time.Hour))
	noSession, _, _ := issuer.Issue("u", "", now)

	publicDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	algConfusion, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, security.AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "u", Issuer: "auth-service", ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))},
		SessionID:        "s",
	}).SignedString(publicDER)

	for name, bad := range map[string]string{
		"foreign key":                         foreign,
		"expired":                             expired,
		"no session id":                       noSession,
		"HS256 with the public key as secret": algConfusion,
		"garbage":                             "a.b.c",
	} {
		if _, err := issuer.Verify(bad, now); !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("%s: err = %v, want ErrUnauthorized", name, err)
		}
	}
}

func TestRefreshTokens(t *testing.T) {
	token, hash, err := security.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if security.CheckRefreshFormat(token) != nil {
		t.Fatalf("generated token must pass the format check: %s", token)
	}
	if string(security.HashRefreshToken(token)) != string(hash) {
		t.Fatal("hash must be deterministic")
	}

	other, _, _ := security.NewRefreshToken()
	if other == token {
		t.Fatal("tokens must be random")
	}

	for _, bad := range []string{"", "rt_short", strings.Repeat("x", len(token)), "xx" + token[2:]} {
		if security.CheckRefreshFormat(bad) == nil {
			t.Errorf("CheckRefreshFormat(%q) must fail", bad)
		}
	}
}
