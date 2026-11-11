// Package postgres - хранилище на PostgreSQL.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"auth/internal/config"
	"auth/internal/domain"
	"auth/internal/usecase"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

const uniqueViolation = "23505"

// queryer - общее у пула и транзакции
type queryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Store struct {
	pool *pgxpool.Pool
	db   queryer
	inTx bool
}

var _ usecase.Store = (*Store)(nil)

// Connect открывает пул соединений и проверяет связь с базой
func Connect(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.ConnectTimeout > 0 {
		poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

// Migrate применяет миграции из migrations/. Повторный запуск ничего не меняет.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	dir, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}

	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, dir)
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, db: pool}
}

func (s *Store) InTx(ctx context.Context, fn func(usecase.Store) error) error {
	if s.inTx {
		return fn(s)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(&Store{pool: s.pool, db: tx, inTx: true})
	})
}

// --- Пользователи ---

const userColumns = `id, email, username, password_hash, failed_logins, locked_until,
	password_changed_at, created_at, updated_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.FailedLogins,
		&u.LockedUntil, &u.PasswordChangedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

func (s *Store) CreateUser(ctx context.Context, u *domain.User) error {
	_, err := s.db.Exec(ctx, `INSERT INTO users (`+userColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		u.ID, u.Email, u.Username, u.PasswordHash, u.FailedLogins, u.LockedUntil,
		u.PasswordChangedAt, u.CreatedAt, u.UpdatedAt)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		switch pgErr.ConstraintName {
		case "users_email_key":
			return domain.ErrEmailTaken
		case "users_username_key":
			return domain.ErrUsernameTaken
		}
		return domain.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email))
}

func (s *Store) RecordLoginFailure(
	ctx context.Context, userID string, maxAttempts int, lockout time.Duration, now time.Time,
) (*time.Time, error) {
	// Одним запросом, без чтения перед записью: параллельные неудачные попытки
	// не потеряют инкременты. В RETURNING новые значения колонок.
	var lockedUntil *time.Time
	err := s.db.QueryRow(ctx, `
		UPDATE users SET
			locked_until  = CASE WHEN failed_logins + 1 >= $2 THEN $3::timestamptz + $4::interval ELSE locked_until END,
			failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END
		WHERE id = $1
		RETURNING CASE WHEN locked_until > $3 THEN locked_until END`,
		userID, maxAttempts, now, lockout).Scan(&lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("record login failure: %w", err)
	}
	return lockedUntil, nil
}

func (s *Store) ResetLoginFailures(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL
		WHERE id = $1 AND (failed_logins > 0 OR locked_until IS NOT NULL)`, userID)
	if err != nil {
		return fmt.Errorf("reset login failures: %w", err)
	}
	return nil
}

func (s *Store) UpdatePassword(ctx context.Context, userID, hash string, now time.Time) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE users SET password_hash = $2, password_changed_at = $3, updated_at = $3 WHERE id = $1`,
		userID, hash, now)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// --- Сессии ---

const sessionColumns = `id, user_id, device_name, device_type, user_agent, ip,
	created_at, last_used_at, expires_at, revoked_at, revoke_reason`

func scanSession(row pgx.Row) (*domain.Session, error) {
	var (
		sess   domain.Session
		reason sql.NullString
	)
	err := row.Scan(&sess.ID, &sess.UserID, &sess.DeviceName, &sess.DeviceType, &sess.UserAgent, &sess.IP,
		&sess.CreatedAt, &sess.LastUsedAt, &sess.ExpiresAt, &sess.RevokedAt, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	sess.RevokeReason = reason.String
	return &sess, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *domain.Session) error {
	_, err := s.db.Exec(ctx, `INSERT INTO sessions (`+sessionColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NULL)`,
		sess.ID, sess.UserID, sess.DeviceName, sess.DeviceType, sess.UserAgent, sess.IP,
		sess.CreatedAt, sess.LastUsedAt, sess.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*domain.Session, error) {
	return scanSession(s.db.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
}

func (s *Store) ListActiveSessions(ctx context.Context, userID string, now time.Time) ([]domain.Session, error) {
	rows, err := s.db.Query(ctx, `SELECT `+sessionColumns+` FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
		ORDER BY last_used_at DESC, id DESC`, userID, now)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := []domain.Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, *sess)
	}
	return sessions, rows.Err()
}

func (s *Store) TouchSession(ctx context.Context, id string, lastUsed, expiresAt time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE sessions SET last_used_at = $2, expires_at = $3 WHERE id = $1`,
		id, lastUsed, expiresAt)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, userID, sessionID, reason string, now time.Time) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE sessions SET revoked_at = $3, revoke_reason = $4
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, sessionID, userID, now, reason)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID, exceptID, reason string, now time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `UPDATE sessions SET revoked_at = $3, revoke_reason = $4
		WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`, userID, exceptID, now, reason)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// --- Refresh-токены ---

func (s *Store) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	_, err := s.db.Exec(ctx, `INSERT INTO refresh_tokens (token_hash, session_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`, t.Hash, t.SessionID, t.CreatedAt, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (s *Store) GetRefreshTokenForUpdate(ctx context.Context, hash []byte) (*domain.RefreshToken, error) {
	if !s.inTx {
		return nil, errors.New("GetRefreshTokenForUpdate must be called inside a transaction")
	}

	var t domain.RefreshToken
	err := s.db.QueryRow(ctx, `SELECT token_hash, session_id, created_at, expires_at, used_at
		FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, hash).
		Scan(&t.Hash, &t.SessionID, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return &t, nil
}

func (s *Store) MarkRefreshTokenUsed(ctx context.Context, hash []byte, now time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE token_hash = $1`, hash, now)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}

// Завершенные и истекшие сессии хранятся еще 30 дней: по ним видно, откуда и когда входили
const sessionRetention = 30 * 24 * time.Hour

func (s *Store) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	// Использованные токены живут до своего срока: пока он не вышел, их повторное
	// предъявление распознается как кража и завершает сессию
	tokens, err := s.db.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}

	sessions, err := s.db.Exec(ctx, `DELETE FROM sessions
		WHERE (revoked_at IS NOT NULL AND revoked_at < $1) OR expires_at < $1`, now.Add(-sessionRetention))
	if err != nil {
		return 0, fmt.Errorf("delete old sessions: %w", err)
	}
	return tokens.RowsAffected() + sessions.RowsAffected(), nil
}
