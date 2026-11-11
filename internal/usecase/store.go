package usecase

import (
	"context"
	"time"

	"auth/internal/domain"
)

// Store - хранилище пользователей, сессий и refresh-токенов.
//
// Бизнес-правила (повторное использование токена, лимит сессий, блокировка входа)
// живут в usecase, а хранилище дает транзакцию: InTx выполняет fn атомарно.
type Store interface {
	InTx(ctx context.Context, fn func(Store) error) error

	CreateUser(ctx context.Context, user *domain.User) error
	GetUserByID(ctx context.Context, id string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	// RecordLoginFailure атомарно увеличивает счетчик неудачных входов. Когда он доходит
	// до maxAttempts, вход блокируется на lockout, а счетчик сбрасывается.
	// Возвращает время окончания блокировки, если она наступила.
	RecordLoginFailure(ctx context.Context, userID string, maxAttempts int, lockout time.Duration, now time.Time) (*time.Time, error)
	ResetLoginFailures(ctx context.Context, userID string) error
	UpdatePassword(ctx context.Context, userID, hash string, now time.Time) error

	CreateSession(ctx context.Context, session *domain.Session) error
	GetSession(ctx context.Context, id string) (*domain.Session, error)
	// ListActiveSessions - действующие сессии пользователя, сначала недавно использованные
	ListActiveSessions(ctx context.Context, userID string, now time.Time) ([]domain.Session, error)
	TouchSession(ctx context.Context, id string, lastUsed, expiresAt time.Time) error
	// RevokeSession завершает сессию пользователя. false - сессии нет или она уже завершена.
	RevokeSession(ctx context.Context, userID, sessionID, reason string, now time.Time) (bool, error)
	// RevokeUserSessions завершает все сессии пользователя, кроме exceptID (если задан)
	RevokeUserSessions(ctx context.Context, userID, exceptID, reason string, now time.Time) (int64, error)

	CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	// GetRefreshTokenForUpdate читает токен с блокировкой строки до конца транзакции:
	// два одновременных обновления одним токеном выполнятся строго по очереди
	GetRefreshTokenForUpdate(ctx context.Context, hash []byte) (*domain.RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, hash []byte, now time.Time) error

	// DeleteExpired удаляет истекшие refresh-токены и давно завершенные сессии
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}
