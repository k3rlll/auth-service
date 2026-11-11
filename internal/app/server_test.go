package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth/internal/app"
	"auth/internal/security"
	"auth/internal/storage/memory"
	httpapi "auth/internal/transport/http"
	"auth/internal/usecase"
)

// Сквозные тесты HTTP API: настоящие маршруты, middleware и usecase поверх хранилища в памяти

type env struct {
	t      *testing.T
	url    string
	issuer *security.TokenIssuer
}

func newEnv(t *testing.T, ipPerMinute int) *env {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := security.NewTokenIssuer(key, "auth-service", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	svc, err := usecase.NewService(memory.New(), security.NewPasswordHasher(64, 1, 1), issuer, usecase.Config{
		RefreshTTL: 24 * time.Hour, RefreshReuseGrace: 10 * time.Second, MaxSessions: 10,
		MinPasswordLength: 8, MaxFailedAttempts: 5, Lockout: time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(app.NewServer(app.Deps{
		Logger:  logger,
		Service: svc,
		Tokens:  issuer,
		Limiter: httpapi.NewIPRateLimiter(ipPerMinute, ipPerMinute),
		Ready:   func(context.Context) error { return nil },
	}))
	t.Cleanup(server.Close)

	return &env{t: t, url: server.URL, issuer: issuer}
}

type response struct {
	status int
	body   []byte
	header http.Header
}

func (e *env) do(method, path, token string, body any, headers ...string) response {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.url+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: raw, header: resp.Header}
}

func (e *env) expect(status int, method, path, token string, body any, headers ...string) []byte {
	e.t.Helper()
	resp := e.do(method, path, token, body, headers...)
	if resp.status != status {
		e.t.Fatalf("%s %s: status %d, want %d, body %s", method, path, resp.status, status, resp.body)
	}
	return resp.body
}

func (e *env) expectCode(status int, code, method, path, token string, body any) {
	e.t.Helper()
	raw := e.expect(status, method, path, token, body)
	var resp httpapi.ErrorResponse
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Error.Code != code {
		e.t.Fatalf("%s %s: code %q, want %q (%s)", method, path, resp.Error.Code, code, raw)
	}
}

func decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

const (
	iphoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
	chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
)

func TestDeviceSessionsFlow(t *testing.T) {
	e := newEnv(t, 1000)

	// Регистрация с ноутбука сразу дает токены
	reg := decode[httpapi.TokensResponse](t, e.expect(http.StatusCreated, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email": "alice@example.com", "username": "alice", "password": "s3cret-password",
		"device": map[string]string{"name": "Рабочий ноутбук", "type": "laptop"},
	}))
	if reg.User == nil || reg.TokenType != "Bearer" || reg.ExpiresIn != 900 || reg.Session.DeviceType != "laptop" {
		t.Fatalf("unexpected register response: %+v", reg)
	}

	// Токен соответствует контракту с другими сервисами: RS256, sub = ULID пользователя
	claims, err := e.issuer.Verify(reg.AccessToken, time.Now())
	if err != nil || claims.Subject != reg.User.ID {
		t.Fatalf("token claims: %+v %v", claims, err)
	}

	// Вход с телефона и из браузера: устройство определяется по User-Agent
	login := func(ua string) httpapi.TokensResponse {
		return decode[httpapi.TokensResponse](t, e.expect(http.StatusOK, http.MethodPost, "/api/v1/auth/login", "",
			map[string]any{"email": "alice@example.com", "password": "s3cret-password"}, "User-Agent", ua))
	}
	phone := login(iphoneUA)
	browser := login(chromeUA)
	if phone.Session.DeviceType != "phone" || browser.Session.DeviceName != "Chrome · Windows" {
		t.Fatalf("device detection: phone=%+v browser=%+v", phone.Session, browser.Session)
	}

	me := decode[httpapi.UserResponse](t, e.expect(http.StatusOK, http.MethodGet, "/api/v1/users/me", phone.AccessToken, nil))
	if me.Email != "alice@example.com" {
		t.Fatalf("me: %+v", me)
	}

	// Список устройств глазами браузера
	list := decode[struct {
		Sessions []httpapi.SessionResponse `json:"sessions"`
	}](t, e.expect(http.StatusOK, http.MethodGet, "/api/v1/sessions", browser.AccessToken, nil))
	if len(list.Sessions) != 3 {
		t.Fatalf("sessions: %+v", list.Sessions)
	}
	current := 0
	for _, s := range list.Sessions {
		if s.Current {
			current++
			if s.ID != browser.Session.ID {
				t.Fatalf("wrong current session: %+v", s)
			}
		}
	}
	if current != 1 {
		t.Fatalf("exactly one session must be current: %+v", list.Sessions)
	}

	// Из браузера завершаем сессию телефона: телефон сразу теряет доступ
	e.expect(http.StatusNoContent, http.MethodDelete, "/api/v1/sessions/"+phone.Session.ID, browser.AccessToken, nil)
	e.expectCode(http.StatusUnauthorized, "UNAUTHORIZED", http.MethodGet, "/api/v1/users/me", phone.AccessToken, nil)
	e.expectCode(http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", http.MethodPost, "/api/v1/auth/refresh", "",
		map[string]string{"refresh_token": phone.RefreshToken})
	e.expectCode(http.StatusNotFound, "NOT_FOUND", http.MethodDelete, "/api/v1/sessions/"+phone.Session.ID, browser.AccessToken, nil)

	// Обновление токенов браузера и попытка повторить старый refresh-токен
	refreshed := decode[httpapi.TokensResponse](t, e.expect(http.StatusOK, http.MethodPost, "/api/v1/auth/refresh", "",
		map[string]string{"refresh_token": browser.RefreshToken}))
	if refreshed.Session.ID != browser.Session.ID || refreshed.RefreshToken == browser.RefreshToken {
		t.Fatalf("refresh: %+v", refreshed)
	}
	e.expectCode(http.StatusConflict, "REFRESH_CONFLICT", http.MethodPost, "/api/v1/auth/refresh", "",
		map[string]string{"refresh_token": browser.RefreshToken})

	// Выход со всех устройств, кроме текущего
	revoked := decode[map[string]int](t, e.expect(http.StatusOK, http.MethodDelete, "/api/v1/sessions", refreshed.AccessToken, nil))
	if revoked["revoked"] != 1 {
		t.Fatalf("revoked: %v", revoked)
	}
	e.expectCode(http.StatusUnauthorized, "UNAUTHORIZED", http.MethodGet, "/api/v1/users/me", reg.AccessToken, nil)

	// Смена пароля и выход
	e.expect(http.StatusNoContent, http.MethodPut, "/api/v1/users/me/password", refreshed.AccessToken,
		map[string]string{"current_password": "s3cret-password", "new_password": "even-better-password"})
	e.expect(http.StatusNoContent, http.MethodPost, "/api/v1/auth/logout", refreshed.AccessToken, nil)
	e.expectCode(http.StatusUnauthorized, "UNAUTHORIZED", http.MethodGet, "/api/v1/sessions", refreshed.AccessToken, nil)
}

func TestErrors(t *testing.T) {
	e := newEnv(t, 1000)
	body := map[string]any{"email": "bob@example.com", "username": "bob", "password": "s3cret-password"}
	e.expect(http.StatusCreated, http.MethodPost, "/api/v1/auth/register", "", body)

	e.expectCode(http.StatusConflict, "EMAIL_TAKEN", http.MethodPost, "/api/v1/auth/register", "", body)
	e.expectCode(http.StatusUnprocessableEntity, "VALIDATION_ERROR", http.MethodPost, "/api/v1/auth/register", "",
		map[string]any{"email": "x@example.com", "device": map[string]string{"type": "toaster"}})
	e.expectCode(http.StatusBadRequest, "INVALID_REQUEST", http.MethodPost, "/api/v1/auth/register", "",
		map[string]any{"email": "not-email", "username": "carol", "password": "s3cret-password"})
	e.expectCode(http.StatusUnauthorized, "INVALID_CREDENTIALS", http.MethodPost, "/api/v1/auth/login", "",
		map[string]any{"email": "bob@example.com", "password": "wrong-password"})
	e.expectCode(http.StatusUnauthorized, "INVALID_CREDENTIALS", http.MethodPost, "/api/v1/auth/login", "",
		map[string]any{"email": "nobody@example.com", "password": "wrong-password"})
	e.expectCode(http.StatusUnauthorized, "UNAUTHORIZED", http.MethodGet, "/api/v1/users/me", "", nil)
	e.expectCode(http.StatusUnauthorized, "UNAUTHORIZED", http.MethodGet, "/api/v1/users/me", "not-a-token", nil)

	// Блокировка после серии неудач, с Retry-After
	for i := 0; i < 4; i++ {
		e.do(http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "bob@example.com", "password": "wrong-password"})
	}
	resp := e.do(http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": "bob@example.com", "password": "s3cret-password"})
	if resp.status != http.StatusTooManyRequests || resp.header.Get("Retry-After") == "" {
		t.Fatalf("lockout: %d %v %s", resp.status, resp.header, resp.body)
	}
}

func TestIPRateLimit(t *testing.T) {
	e := newEnv(t, 3)
	login := map[string]any{"email": "x@example.com", "password": "whatever-password"}

	for i := 0; i < 3; i++ {
		e.expect(http.StatusUnauthorized, http.MethodPost, "/api/v1/auth/login", "", login)
	}
	resp := e.do(http.MethodPost, "/api/v1/auth/login", "", login)
	if resp.status != http.StatusTooManyRequests || resp.header.Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d %v", resp.status, resp.header)
	}

	// Подмена X-Forwarded-For не помогает: без доверенного прокси заголовок игнорируется
	resp = e.do(http.MethodPost, "/api/v1/auth/login", "", login, "X-Forwarded-For", "203.0.113.7")
	if resp.status != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Forwarded-For bypassed the limit: %d", resp.status)
	}
}

func TestJWKSAndProbes(t *testing.T) {
	e := newEnv(t, 1000)

	jwks := decode[struct {
		Keys []security.JWK `json:"keys"`
	}](t, e.expect(http.StatusOK, http.MethodGet, "/.well-known/jwks.json", "", nil))
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyType != "RSA" || jwks.Keys[0].Algorithm != "RS256" ||
		jwks.Keys[0].N == "" || jwks.Keys[0].E != "AQAB" {
		t.Fatalf("jwks: %+v", jwks)
	}

	e.expect(http.StatusOK, http.MethodGet, "/healthz", "", nil)
	e.expect(http.StatusOK, http.MethodGet, "/readyz", "", nil)
	e.expectCode(http.StatusNotFound, "NOT_FOUND", http.MethodGet, "/nope", "", nil)
}
