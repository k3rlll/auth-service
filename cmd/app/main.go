package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"auth/internal/app"
	"auth/internal/config"
	"auth/internal/security"
	"auth/internal/storage/postgres"
	httpapi "auth/internal/transport/http"
	"auth/internal/usecase"
	"auth/pkg/logger"
)

func main() {
	if err := run(); err != nil {
		slog.Error("service stopped with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(cfg.Environment)

	privateKey, err := security.LoadPrivateKey(cfg.Tokens.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("%w (create a key pair with: go run ./cmd/keygen)", err)
	}
	tokens, err := security.NewTokenIssuer(privateKey, cfg.Tokens.Issuer, cfg.Tokens.AccessTTL)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	initCtx, cancelInit := context.WithTimeout(ctx, 30*time.Second)
	defer cancelInit()

	pool, err := postgres.Connect(initCtx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := postgres.Migrate(initCtx, pool); err != nil {
		return err
	}

	service, err := usecase.NewService(
		postgres.New(pool),
		security.NewPasswordHasher(cfg.Password.MemoryKiB, cfg.Password.Iterations, cfg.Password.Parallelism),
		tokens,
		usecase.Config{
			RefreshTTL:        cfg.Tokens.RefreshTTL,
			RefreshReuseGrace: cfg.Tokens.RefreshReuseGrace,
			MaxSessions:       cfg.Sessions.MaxPerUser,
			MinPasswordLength: cfg.Password.MinLength,
			MaxFailedAttempts: cfg.LoginProtection.MaxFailedAttempts,
			Lockout:           cfg.LoginProtection.Lockout,
		},
		log,
	)
	if err != nil {
		return err
	}

	limiter := httpapi.NewIPRateLimiter(cfg.LoginProtection.IPRatePerMinute, cfg.LoginProtection.IPBurst)

	// Фоновые задачи: чистка истекших токенов и карты лимитов по IP
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		runCleanup(ctx, service, cfg.Sessions.CleanupInterval, log)
	}()
	go func() {
		defer workers.Done()
		limiter.RunCleanup(ctx, 5*time.Minute)
	}()

	server := app.NewServer(app.Deps{
		Logger:     log,
		Service:    service,
		Tokens:     tokens,
		Limiter:    limiter,
		Ready:      pool.Ping,
		TrustProxy: cfg.Server.TrustProxy,
	})

	serverErr := make(chan error, 1)
	go func() {
		addr := net.JoinHostPort(cfg.Server.Host, cfg.Server.Port)
		log.Info("starting auth service", "addr", addr)
		if err := server.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		stop()
		workers.Wait()
		return fmt.Errorf("start server: %w", err)
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	workers.Wait()

	log.Info("auth service stopped gracefully")
	return nil
}

func runCleanup(ctx context.Context, service *usecase.Service, every time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := service.CleanupExpired(ctx)
			if err != nil {
				log.Error("cleanup of expired tokens failed", "error", err)
				continue
			}
			if n > 0 {
				log.Info("expired tokens and sessions removed", "count", n)
			}
		}
	}
}
