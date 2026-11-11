//go:build integration

// Интеграционные тесты против настоящего PostgreSQL (testcontainers):
// миграции, ограничения уникальности, атомарный счетчик неудачных входов
// и построчная блокировка при одновременном обновлении токенов.
//
//	go test -tags integration ./internal/storage/...
package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"auth/internal/config"
	"auth/internal/domain"
	"auth/internal/security"
	"auth/internal/storage/postgres"
	"auth/internal/usecase"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("auth"),
		tcpostgres.WithUsername("auth"),
		tcpostgres.WithPassword("auth"),
		tcpostgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, container)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	url, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}

	pool, err := postgres.Connect(ctx, config.DatabaseConfig{URL: url, MaxConns: 10, ConnectTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrations must be idempotent: %v", err)
	}
	return pool
}

func newUser(email, username string) *domain.User {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.User{
		ID: ulid.Make().String(), Email: email, Username: username, PasswordHash: "hash",
		PasswordChangedAt: now, CreatedAt: now, UpdatedAt: now,
	}
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	store := postgres.New(newPool(t))

	alice := newUser("alice@example.com", "alice")
	if err := store.CreateUser(ctx, alice); err != nil {
		t.Fatal(err)
	}

	t.Run("unique email and username ignore case", func(t *testing.T) {
		if err := store.CreateUser(ctx, newUser("ALICE@example.com", "other")); !errors.Is(err, domain.ErrEmailTaken) {
			t.Fatalf("err = %v, want ErrEmailTaken", err)
		}
		if err := store.CreateUser(ctx, newUser("other@example.com", "Alice")); !errors.Is(err, domain.ErrUsernameTaken) {
			t.Fatalf("err = %v, want ErrUsernameTaken", err)
		}
		got, err := store.GetUserByEmail(ctx, "Alice@Example.com")
		if err != nil || got.ID != alice.ID {
			t.Fatalf("lookup by email ignores case: %+v %v", got, err)
		}
	})

	t.Run("login failures lock the account atomically", func(t *testing.T) {
		now := time.Now().UTC()

		// 10 одновременных неудач при лимите 5: ровно две блокировки, ни один инкремент не потерян
		var wg sync.WaitGroup
		var mu sync.Mutex
		locks := 0
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				until, err := store.RecordLoginFailure(ctx, alice.ID, 5, 5*time.Minute, now)
				if err != nil {
					t.Error(err)
					return
				}
				if until != nil {
					mu.Lock()
					locks++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		got, _ := store.GetUserByID(ctx, alice.ID)
		if got.FailedLogins != 0 || got.LockedUntil == nil || !got.IsLocked(now) {
			t.Fatalf("user after failures: %+v", got)
		}
		if locks < 2 {
			t.Fatalf("every 5th failure must lock, locks = %d", locks)
		}

		if err := store.ResetLoginFailures(ctx, alice.ID); err != nil {
			t.Fatal(err)
		}
		got, _ = store.GetUserByID(ctx, alice.ID)
		if got.LockedUntil != nil || got.FailedLogins != 0 {
			t.Fatalf("reset: %+v", got)
		}
	})

	t.Run("transaction rolls back on error", func(t *testing.T) {
		bob := newUser("bob@example.com", "bob")
		err := store.InTx(ctx, func(tx usecase.Store) error {
			if err := tx.CreateUser(ctx, bob); err != nil {
				return err
			}
			return errors.New("boom")
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if _, err := store.GetUserByID(ctx, bob.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("user must not be committed: %v", err)
		}
	})
}

// Полный сценарий usecase поверх PostgreSQL, включая гонку двух обновлений одним токеном
func TestServiceOnPostgres(t *testing.T) {
	ctx := context.Background()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, _ := security.NewTokenIssuer(key, "auth-service", 15*time.Minute)

	svc, err := usecase.NewService(postgres.New(newPool(t)), security.NewPasswordHasher(64, 1, 1), issuer, usecase.Config{
		RefreshTTL: 24 * time.Hour, RefreshReuseGrace: 10 * time.Second, MaxSessions: 3,
		MinPasswordLength: 8, MaxFailedAttempts: 5, Lockout: time.Minute,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	reg, err := svc.Register(ctx, usecase.RegisterParams{Email: "alice@example.com", Username: "alice", Password: "s3cret-password"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("concurrent refresh with the same token", func(t *testing.T) {
		// Строка токена блокируется FOR UPDATE: выигрывает ровно один запрос,
		// второй видит токен уже использованным (в пределах окна - конфликт, не кража)
		const n = 8
		results := make(chan error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := svc.Refresh(ctx, reg.Tokens.RefreshToken)
				results <- err
			}()
		}
		wg.Wait()
		close(results)

		ok, conflicts := 0, 0
		for err := range results {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, domain.ErrRefreshConflict):
				conflicts++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if ok != 1 || conflicts != n-1 {
			t.Fatalf("ok=%d conflicts=%d, want exactly one winner", ok, conflicts)
		}
	})

	t.Run("session limit and device list", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			if _, err := svc.Login(ctx, "alice@example.com", "s3cret-password", usecase.Device{Name: "device", Type: domain.DevicePhone}); err != nil {
				t.Fatal(err)
			}
		}
		sessions, err := svc.ListSessions(ctx, reg.User.ID, "")
		if err != nil || len(sessions) != 3 {
			t.Fatalf("sessions: %d %v", len(sessions), err)
		}
		if _, _, err := svc.Authenticate(ctx, reg.Tokens.AccessToken); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatal("the oldest session must have been ended by the limit")
		}
	})

	t.Run("cleanup", func(t *testing.T) {
		if _, err := svc.CleanupExpired(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
