package usecase_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"auth/internal/domain"
	"auth/internal/security"
	"auth/internal/storage/memory"
	"auth/internal/usecase"
)

// clock - управляемое время
type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type env struct {
	svc   *usecase.Service
	store *memory.Store
	clock *clock
}

var testKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

func newEnv(t *testing.T, mutate ...func(*usecase.Config)) *env {
	t.Helper()
	cfg := usecase.Config{
		RefreshTTL:        30 * 24 * time.Hour,
		RefreshReuseGrace: 10 * time.Second,
		MaxSessions:       5,
		MinPasswordLength: 8,
		MaxFailedAttempts: 3,
		Lockout:           5 * time.Minute,
	}
	for _, m := range mutate {
		m(&cfg)
	}

	tokens, err := security.NewTokenIssuer(testKey, "auth-service", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	svc, err := usecase.NewService(store, security.NewPasswordHasher(64, 1, 1), tokens, cfg,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	c := &clock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc.SetClock(c.Now)
	return &env{svc: svc, store: store, clock: c}
}

var ctx = context.Background()

const password = "s3cret-password"

func (e *env) register(t *testing.T, email, username string) *usecase.AuthResult {
	t.Helper()
	res, err := e.svc.Register(ctx, usecase.RegisterParams{
		Email: email, Username: username, Password: password,
		Device: usecase.Device{Name: "registration device", Type: domain.DeviceWeb},
	})
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	return res
}

func (e *env) login(t *testing.T, email, device string) *usecase.AuthResult {
	t.Helper()
	res, err := e.svc.Login(ctx, email, password, usecase.Device{Name: device, Type: domain.DevicePhone})
	if err != nil {
		t.Fatalf("login from %s: %v", device, err)
	}
	return res
}

func (e *env) authenticated(res *usecase.AuthResult) bool {
	_, _, err := e.svc.Authenticate(ctx, res.Tokens.AccessToken)
	return err == nil
}

func TestRegister(t *testing.T) {
	e := newEnv(t)
	res := e.register(t, "  Alice@Example.COM ", "alice")

	if res.User.Email != "alice@example.com" {
		t.Fatalf("email must be normalized, got %q", res.User.Email)
	}
	if res.Session == nil || res.Tokens.AccessToken == "" || res.Tokens.RefreshToken == "" {
		t.Fatalf("registration must log the user in: %+v", res)
	}
	if !e.authenticated(res) {
		t.Fatal("access token from registration must work")
	}

	cases := map[string]struct {
		p    usecase.RegisterParams
		want error
	}{
		"same email in another case": {usecase.RegisterParams{Email: "ALICE@example.com", Username: "alice2", Password: password}, domain.ErrEmailTaken},
		"same username":              {usecase.RegisterParams{Email: "a2@example.com", Username: "ALICE", Password: password}, domain.ErrUsernameTaken},
		"invalid email":              {usecase.RegisterParams{Email: "not-an-email", Username: "bob", Password: password}, domain.ErrInvalidInput},
		"email with display name":    {usecase.RegisterParams{Email: "Bob <bob@example.com>", Username: "bob", Password: password}, domain.ErrInvalidInput},
		"short username":             {usecase.RegisterParams{Email: "bob@example.com", Username: "bo", Password: password}, domain.ErrInvalidInput},
		"username with spaces":       {usecase.RegisterParams{Email: "bob@example.com", Username: "bob smith", Password: password}, domain.ErrInvalidInput},
		"short password":             {usecase.RegisterParams{Email: "bob@example.com", Username: "bob", Password: "1234567"}, domain.ErrInvalidInput},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := e.svc.Register(ctx, tc.p); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLoginAndLockout(t *testing.T) {
	e := newEnv(t)
	e.register(t, "alice@example.com", "alice")

	if _, err := e.svc.Login(ctx, "ghost@example.com", password, usecase.Device{}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("unknown email: err = %v", err)
	}

	// Две неудачи из трех допустимых, затем успешный вход сбрасывает счетчик
	for i := 0; i < 2; i++ {
		if _, err := e.svc.Login(ctx, "alice@example.com", "wrong", usecase.Device{}); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("wrong password: err = %v", err)
		}
	}
	e.login(t, "ALICE@example.com", "phone")
	for i := 0; i < 2; i++ {
		if _, err := e.svc.Login(ctx, "alice@example.com", "wrong", usecase.Device{}); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("counter must have been reset, attempt %d: err = %v", i, err)
		}
	}

	// Третья неудача подряд блокирует вход
	_, err := e.svc.Login(ctx, "alice@example.com", "wrong", usecase.Device{})
	var locked *domain.LockedError
	if !errors.As(err, &locked) || !locked.Until.Equal(e.clock.now.Add(5*time.Minute)) {
		t.Fatalf("expected lockout, got %v", err)
	}

	// Во время блокировки не пускает даже с верным паролем
	if _, err := e.svc.Login(ctx, "alice@example.com", password, usecase.Device{}); !errors.As(err, &locked) {
		t.Fatalf("correct password during lockout: err = %v", err)
	}

	e.clock.Advance(5*time.Minute + time.Second)
	e.login(t, "alice@example.com", "phone")
}

func TestDeviceSessions(t *testing.T) {
	e := newEnv(t)
	reg := e.register(t, "alice@example.com", "alice")
	phone := e.login(t, "alice@example.com", "iPhone")
	e.clock.Advance(time.Minute)
	laptop := e.login(t, "alice@example.com", "MacBook")

	sessions, err := e.svc.ListSessions(ctx, reg.User.ID, laptop.Session.ID)
	if err != nil || len(sessions) != 3 {
		t.Fatalf("sessions: %d %v", len(sessions), err)
	}
	if sessions[0].ID != laptop.Session.ID || !sessions[0].Current {
		t.Fatalf("most recent session first and marked current: %+v", sessions[0])
	}

	// Выход на телефоне с ноутбука
	if err := e.svc.RevokeSession(ctx, reg.User.ID, laptop.Session.ID, phone.Session.ID); err != nil {
		t.Fatal(err)
	}
	if e.authenticated(phone) || !e.authenticated(laptop) {
		t.Fatal("only the phone session must end")
	}
	if _, err := e.svc.Refresh(ctx, phone.Tokens.RefreshToken); !errors.Is(err, domain.ErrInvalidRefresh) {
		t.Fatalf("refresh of an ended session: err = %v", err)
	}

	// Чужую сессию завершить нельзя
	bob := e.register(t, "bob@example.com", "bob")
	if err := e.svc.RevokeSession(ctx, bob.User.ID, bob.Session.ID, laptop.Session.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("foreign session: err = %v", err)
	}

	// Выход везде, кроме текущего устройства
	n, err := e.svc.RevokeOtherSessions(ctx, reg.User.ID, laptop.Session.ID)
	if err != nil || n != 1 {
		t.Fatalf("revoked %d, err %v", n, err)
	}
	if e.authenticated(reg) || !e.authenticated(laptop) {
		t.Fatal("all but the current session must end")
	}

	if err := e.svc.Logout(ctx, reg.User.ID, laptop.Session.ID); err != nil {
		t.Fatal(err)
	}
	if e.authenticated(laptop) {
		t.Fatal("logout must end the session")
	}
	if err := e.svc.Logout(ctx, reg.User.ID, laptop.Session.ID); err != nil {
		t.Fatalf("logout must be idempotent: %v", err)
	}
}

func TestSessionLimit(t *testing.T) {
	e := newEnv(t, func(c *usecase.Config) { c.MaxSessions = 3 })
	first := e.register(t, "alice@example.com", "alice")

	var later []*usecase.AuthResult
	for i := 0; i < 3; i++ {
		e.clock.Advance(time.Minute)
		later = append(later, e.login(t, "alice@example.com", "device"))
	}

	sessions, _ := e.svc.ListSessions(ctx, first.User.ID, "")
	if len(sessions) != 3 {
		t.Fatalf("active sessions = %d, want 3", len(sessions))
	}
	if e.authenticated(first) {
		t.Fatal("the least recently used session must be ended")
	}
	for _, r := range later {
		if !e.authenticated(r) {
			t.Fatal("newer sessions must stay active")
		}
	}
}

func TestRefreshRotation(t *testing.T) {
	e := newEnv(t)
	first := e.register(t, "alice@example.com", "alice")

	e.clock.Advance(time.Hour)
	second, err := e.svc.Refresh(ctx, first.Tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if second.Tokens.RefreshToken == first.Tokens.RefreshToken || second.Session.ID != first.Session.ID {
		t.Fatal("refresh must rotate the token within the same session")
	}
	if !second.Tokens.RefreshExpiresAt.Equal(e.clock.now.Add(30 * 24 * time.Hour)) {
		t.Fatal("refresh must extend the session (sliding expiry)")
	}
	if !e.authenticated(second) {
		t.Fatal("new access token must work")
	}

	t.Run("retry within grace period is a conflict, not theft", func(t *testing.T) {
		e.clock.Advance(5 * time.Second)
		if _, err := e.svc.Refresh(ctx, first.Tokens.RefreshToken); !errors.Is(err, domain.ErrRefreshConflict) {
			t.Fatalf("err = %v, want ErrRefreshConflict", err)
		}
		if !e.authenticated(second) {
			t.Fatal("session must survive a client retry")
		}
	})

	t.Run("reuse after grace period ends the session", func(t *testing.T) {
		e.clock.Advance(time.Minute)
		if _, err := e.svc.Refresh(ctx, first.Tokens.RefreshToken); !errors.Is(err, domain.ErrRefreshReused) {
			t.Fatalf("err = %v, want ErrRefreshReused", err)
		}
		// Отзыв должен сохраниться, хотя вызов вернул ошибку
		if e.authenticated(second) {
			t.Fatal("stolen token reuse must end the whole session")
		}
		if _, err := e.svc.Refresh(ctx, second.Tokens.RefreshToken); !errors.Is(err, domain.ErrInvalidRefresh) {
			t.Fatalf("legitimate token of the ended session: err = %v", err)
		}
	})

	t.Run("expired session", func(t *testing.T) {
		res := e.login(t, "alice@example.com", "old phone")
		e.clock.Advance(31 * 24 * time.Hour)
		if _, err := e.svc.Refresh(ctx, res.Tokens.RefreshToken); !errors.Is(err, domain.ErrInvalidRefresh) {
			t.Fatalf("err = %v, want ErrInvalidRefresh", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		for _, bad := range []string{"", "rt_nope", strings.Repeat("a", 46)} {
			if _, err := e.svc.Refresh(ctx, bad); !errors.Is(err, domain.ErrInvalidRefresh) {
				t.Errorf("%q: err = %v", bad, err)
			}
		}
	})
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t)
	current := e.register(t, "alice@example.com", "alice")
	other := e.login(t, "alice@example.com", "lost phone")
	userID := current.User.ID

	if err := e.svc.ChangePassword(ctx, userID, current.Session.ID, "wrong", "new-password-1"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("wrong current password: err = %v", err)
	}
	if err := e.svc.ChangePassword(ctx, userID, current.Session.ID, password, password); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("same password: err = %v", err)
	}
	if err := e.svc.ChangePassword(ctx, userID, current.Session.ID, password, "short"); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("weak password: err = %v", err)
	}

	if err := e.svc.ChangePassword(ctx, userID, current.Session.ID, password, "new-password-1"); err != nil {
		t.Fatal(err)
	}
	if !e.authenticated(current) || e.authenticated(other) {
		t.Fatal("password change must end every session except the current one")
	}
	if _, err := e.svc.Login(ctx, "alice@example.com", password, usecase.Device{}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal("old password must stop working")
	}
	if _, err := e.svc.Login(ctx, "alice@example.com", "new-password-1", usecase.Device{}); err != nil {
		t.Fatalf("new password: %v", err)
	}
}

func TestDeviceDetection(t *testing.T) {
	e := newEnv(t)
	e.register(t, "alice@example.com", "alice")

	cases := []struct {
		device   usecase.Device
		wantName string
		wantType string
	}{
		{usecase.Device{UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"},
			"Safari · iPhone", domain.DevicePhone},
		{usecase.Device{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"},
			"Chrome · Windows", domain.DeviceWeb},
		{usecase.Device{UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36"},
			"Chrome · Android", domain.DevicePhone},
		{usecase.Device{Name: "  Рабочий ноутбук  ", Type: "LAPTOP", UserAgent: "MessengerApp/1.0"},
			"Рабочий ноутбук", domain.DeviceLaptop},
		{usecase.Device{Type: "toaster", UserAgent: "curl/8.5.0"}, "curl/8.5.0", domain.DeviceOther},
		{usecase.Device{}, "Unknown device", domain.DeviceOther},
	}
	for _, tc := range cases {
		res, err := e.svc.Login(ctx, "alice@example.com", password, tc.device)
		if err != nil {
			t.Fatal(err)
		}
		if res.Session.DeviceName != tc.wantName || res.Session.DeviceType != tc.wantType {
			t.Errorf("%+v: got %q/%q, want %q/%q", tc.device, res.Session.DeviceName, res.Session.DeviceType, tc.wantName, tc.wantType)
		}
	}
}

func TestCleanupExpired(t *testing.T) {
	e := newEnv(t)
	res := e.register(t, "alice@example.com", "alice")
	e.clock.Advance(61 * 24 * time.Hour)

	n, err := e.svc.CleanupExpired(ctx)
	if err != nil || n != 2 { // refresh-токен и истекшая больше 30 дней назад сессия
		t.Fatalf("removed %d, err %v", n, err)
	}
	if _, err := e.svc.Refresh(ctx, res.Tokens.RefreshToken); !errors.Is(err, domain.ErrInvalidRefresh) {
		t.Fatalf("err = %v", err)
	}
}
