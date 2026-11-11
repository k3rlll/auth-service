// Package usecase - бизнес-логика сервиса авторизации.
package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"auth/internal/domain"
	"auth/internal/security"

	"github.com/oklog/ulid/v2"
)

const maxPasswordLength = 128

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.]{3,32}$`)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encoded string) (bool, error)
}

type TokenIssuer interface {
	Issue(userID, sessionID string, now time.Time) (string, time.Time, error)
	Verify(token string, now time.Time) (*security.AccessClaims, error)
}

type Config struct {
	RefreshTTL        time.Duration
	RefreshReuseGrace time.Duration
	MaxSessions       int
	MinPasswordLength int
	MaxFailedAttempts int
	Lockout           time.Duration
}

type Service struct {
	store  Store
	hasher PasswordHasher
	tokens TokenIssuer
	cfg    Config
	logger *slog.Logger
	now    func() time.Time

	// Хэш для несуществующих пользователей: проверка пароля идет всегда,
	// и по времени ответа нельзя понять, зарегистрирован ли email
	dummyHash string
}

func NewService(store Store, hasher PasswordHasher, tokens TokenIssuer, cfg Config, logger *slog.Logger) (*Service, error) {
	dummy, err := hasher.Hash("dummy password for timing equalization")
	if err != nil {
		return nil, err
	}
	return &Service{
		store:     store,
		hasher:    hasher,
		tokens:    tokens,
		cfg:       cfg,
		logger:    logger,
		now:       func() time.Time { return time.Now().UTC() },
		dummyHash: dummy,
	}, nil
}

// SetClock подменяет часы (для тестов)
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Device - описание устройства, с которого выполняется вход
type Device struct {
	Name      string // "iPhone 15", "Рабочий ноутбук"; пустое - определится по User-Agent
	Type      string // phone, tablet, desktop, laptop, web, other
	UserAgent string
	IP        string
}

type Tokens struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type AuthResult struct {
	User    *domain.User
	Session *domain.Session
	Tokens  Tokens
}

type RegisterParams struct {
	Email    string
	Username string
	Password string
	Device   Device
}

// Register создает пользователя и сразу открывает сессию на этом устройстве
func (s *Service) Register(ctx context.Context, p RegisterParams) (*AuthResult, error) {
	email, err := normalizeEmail(p.Email)
	if err != nil {
		return nil, err
	}
	username := strings.TrimSpace(p.Username)
	if !usernamePattern.MatchString(username) {
		return nil, domain.Invalid("username must be 3-32 characters: letters, digits, '_' and '.'")
	}
	if err := s.checkPassword(p.Password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(p.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := s.now()
	user := &domain.User{
		ID:                ulid.Make().String(),
		Email:             email,
		Username:          username,
		PasswordHash:      hash,
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	var result *AuthResult
	err = s.store.InTx(ctx, func(tx Store) error {
		if err := tx.CreateUser(ctx, user); err != nil {
			return err
		}
		result, err = s.openSession(ctx, tx, user, p.Device, now)
		return err
	})
	if err != nil {
		if errors.Is(err, domain.ErrEmailTaken) || errors.Is(err, domain.ErrUsernameTaken) {
			return nil, err
		}
		return nil, fmt.Errorf("register: %w", err)
	}

	s.logger.InfoContext(ctx, "user registered", "userID", user.ID, "sessionID", result.Session.ID)
	return result, nil
}

// Login проверяет пароль и открывает новую сессию для устройства.
// На любую ошибку учетных данных отвечает одинаково: ErrInvalidCredentials.
func (s *Service) Login(ctx context.Context, email, password string, device Device) (*AuthResult, error) {
	now := s.now()

	user, err := s.store.GetUserByEmail(ctx, strings.TrimSpace(email))
	if errors.Is(err, domain.ErrNotFound) {
		_, _ = s.hasher.Verify(password, s.dummyHash)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	if user.IsLocked(now) {
		return nil, &domain.LockedError{Until: *user.LockedUntil}
	}

	ok, err := s.hasher.Verify(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		lockedUntil, err := s.store.RecordLoginFailure(ctx, user.ID, s.cfg.MaxFailedAttempts, s.cfg.Lockout, now)
		if err != nil {
			return nil, fmt.Errorf("record login failure: %w", err)
		}
		if lockedUntil != nil {
			s.logger.WarnContext(ctx, "account locked after failed logins", "userID", user.ID, "until", *lockedUntil)
			return nil, &domain.LockedError{Until: *lockedUntil}
		}
		return nil, domain.ErrInvalidCredentials
	}

	var result *AuthResult
	err = s.store.InTx(ctx, func(tx Store) error {
		if err := tx.ResetLoginFailures(ctx, user.ID); err != nil {
			return err
		}
		result, err = s.openSession(ctx, tx, user, device, now)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	s.logger.InfoContext(ctx, "user logged in",
		"userID", user.ID, "sessionID", result.Session.ID, "device", result.Session.DeviceType)
	return result, nil
}

// openSession создает сессию устройства и первую пару токенов.
// Если активных сессий слишком много, завершает самые давно неиспользованные.
func (s *Service) openSession(ctx context.Context, tx Store, user *domain.User, device Device, now time.Time) (*AuthResult, error) {
	active, err := tx.ListActiveSessions(ctx, user.ID, now)
	if err != nil {
		return nil, err
	}
	// Список отсортирован от недавних к давним: лишние - в конце
	for i := s.cfg.MaxSessions - 1; i >= 0 && i < len(active); i++ {
		if _, err := tx.RevokeSession(ctx, user.ID, active[i].ID, domain.RevokeSessionLimit, now); err != nil {
			return nil, err
		}
	}

	device = normalizeDevice(device)
	session := &domain.Session{
		ID:         ulid.Make().String(),
		UserID:     user.ID,
		DeviceName: device.Name,
		DeviceType: device.Type,
		UserAgent:  device.UserAgent,
		IP:         device.IP,
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(s.cfg.RefreshTTL),
	}
	if err := tx.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	tokens, err := s.issueTokens(ctx, tx, session, now)
	if err != nil {
		return nil, err
	}
	return &AuthResult{User: user, Session: session, Tokens: *tokens}, nil
}

// issueTokens выпускает access-токен и новый refresh-токен сессии
func (s *Service) issueTokens(ctx context.Context, tx Store, session *domain.Session, now time.Time) (*Tokens, error) {
	refresh, hash, err := security.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	err = tx.CreateRefreshToken(ctx, &domain.RefreshToken{
		Hash:      hash,
		SessionID: session.ID,
		CreatedAt: now,
		ExpiresAt: session.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}

	access, accessExpires, err := s.tokens.Issue(session.UserID, session.ID, now)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:      access,
		AccessExpiresAt:  accessExpires,
		RefreshToken:     refresh,
		RefreshExpiresAt: session.ExpiresAt,
	}, nil
}

// Refresh обменивает refresh-токен на новую пару токенов (ротация).
//
// Каждый refresh-токен одноразовый. Если уже использованный токен предъявлен снова,
// значит его копия есть у кого-то еще: сессия завершается целиком, и злоумышленник,
// и владелец теряют доступ, владелец входит заново. Исключение - повтор в пределах
// RefreshReuseGrace: так выглядит ретрай самого клиента после обрыва связи,
// ему возвращается ErrRefreshConflict без завершения сессии.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*AuthResult, error) {
	if security.CheckRefreshFormat(refreshToken) != nil {
		return nil, domain.ErrInvalidRefresh
	}
	hash := security.HashRefreshToken(refreshToken)
	now := s.now()

	var (
		result *AuthResult
		reused *domain.Session
	)
	err := s.store.InTx(ctx, func(tx Store) error {
		token, err := tx.GetRefreshTokenForUpdate(ctx, hash)
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrInvalidRefresh
		}
		if err != nil {
			return err
		}

		session, err := tx.GetSession(ctx, token.SessionID)
		if err != nil {
			return err
		}
		if !session.IsActive(now) || !now.Before(token.ExpiresAt) {
			return domain.ErrInvalidRefresh
		}

		if token.UsedAt != nil {
			if now.Sub(*token.UsedAt) <= s.cfg.RefreshReuseGrace {
				return domain.ErrRefreshConflict
			}
			// Завершение сессии должно сохраниться, поэтому транзакция завершается успешно,
			// а ошибка возвращается после нее
			if _, err := tx.RevokeSession(ctx, session.UserID, session.ID, domain.RevokeTokenReuse, now); err != nil {
				return err
			}
			reused = session
			return nil
		}

		if err := tx.MarkRefreshTokenUsed(ctx, hash, now); err != nil {
			return err
		}
		session.LastUsedAt = now
		session.ExpiresAt = now.Add(s.cfg.RefreshTTL) // скользящий срок сессии
		if err := tx.TouchSession(ctx, session.ID, session.LastUsedAt, session.ExpiresAt); err != nil {
			return err
		}

		tokens, err := s.issueTokens(ctx, tx, session, now)
		if err != nil {
			return err
		}
		result = &AuthResult{Session: session, Tokens: *tokens}
		return nil
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidRefresh) || errors.Is(err, domain.ErrRefreshConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("refresh: %w", err)
	}

	if reused != nil {
		s.logger.WarnContext(ctx, "refresh token reuse detected, session revoked",
			"userID", reused.UserID, "sessionID", reused.ID)
		return nil, domain.ErrRefreshReused
	}
	return result, nil
}

// Authenticate проверяет access-токен и то, что его сессия еще действует.
// В отличие от других сервисов, которые проверяют только подпись, здесь выход
// с устройства действует мгновенно, а не после истечения access-токена.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (userID, sessionID string, err error) {
	now := s.now()
	claims, err := s.tokens.Verify(accessToken, now)
	if err != nil {
		return "", "", domain.ErrUnauthorized
	}

	session, err := s.store.GetSession(ctx, claims.SessionID)
	if errors.Is(err, domain.ErrNotFound) {
		return "", "", domain.ErrUnauthorized
	}
	if err != nil {
		return "", "", fmt.Errorf("authenticate: %w", err)
	}
	if session.UserID != claims.Subject || !session.IsActive(now) {
		return "", "", domain.ErrUnauthorized
	}
	return claims.Subject, claims.SessionID, nil
}

func (s *Service) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	return s.store.GetUserByID(ctx, userID)
}

// Logout завершает текущую сессию. Повторный вызов не ошибка.
func (s *Service) Logout(ctx context.Context, userID, sessionID string) error {
	if _, err := s.store.RevokeSession(ctx, userID, sessionID, domain.RevokeLogout, s.now()); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	return nil
}

// SessionView - сессия глазами владельца
type SessionView struct {
	domain.Session
	Current bool
}

// ListSessions - активные устройства пользователя. Текущее помечено.
func (s *Service) ListSessions(ctx context.Context, userID, currentSessionID string) ([]SessionView, error) {
	sessions, err := s.store.ListActiveSessions(ctx, userID, s.now())
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	views := make([]SessionView, len(sessions))
	for i, session := range sessions {
		views[i] = SessionView{Session: session, Current: session.ID == currentSessionID}
	}
	return views, nil
}

// RevokeSession завершает сессию на другом (или этом же) устройстве.
// Чужую сессию завершить нельзя: для нее ответ такой же, как для несуществующей.
func (s *Service) RevokeSession(ctx context.Context, userID, currentSessionID, targetSessionID string) error {
	reason := domain.RevokeByUser
	if targetSessionID == currentSessionID {
		reason = domain.RevokeLogout
	}

	revoked, err := s.store.RevokeSession(ctx, userID, targetSessionID, reason, s.now())
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if !revoked {
		return domain.ErrNotFound
	}
	return nil
}

// RevokeOtherSessions завершает все сессии, кроме текущей. Возвращает их число.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) (int64, error) {
	n, err := s.store.RevokeUserSessions(ctx, userID, currentSessionID, domain.RevokeLogoutOthers, s.now())
	if err != nil {
		return 0, fmt.Errorf("revoke other sessions: %w", err)
	}
	return n, nil
}

// ChangePassword меняет пароль и завершает все остальные сессии:
// если пароль меняют из-за утечки, чужие устройства должны потерять доступ
func (s *Service) ChangePassword(ctx context.Context, userID, currentSessionID, oldPassword, newPassword string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	ok, err := s.hasher.Verify(oldPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return domain.Invalid("current password is incorrect")
	}
	if oldPassword == newPassword {
		return domain.Invalid("new password must differ from the current one")
	}
	if err := s.checkPassword(newPassword); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := s.now()
	err = s.store.InTx(ctx, func(tx Store) error {
		if err := tx.UpdatePassword(ctx, userID, hash, now); err != nil {
			return err
		}
		_, err := tx.RevokeUserSessions(ctx, userID, currentSessionID, domain.RevokePasswordChange, now)
		return err
	})
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	s.logger.InfoContext(ctx, "password changed, other sessions revoked", "userID", userID)
	return nil
}

// CleanupExpired удаляет истекшие токены и старые сессии
func (s *Service) CleanupExpired(ctx context.Context) (int64, error) {
	return s.store.DeleteExpired(ctx, s.now())
}

func (s *Service) checkPassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < s.cfg.MinPasswordLength || n > maxPasswordLength {
		return domain.Invalid(fmt.Sprintf("password must be %d-%d characters long", s.cfg.MinPasswordLength, maxPasswordLength))
	}
	return nil
}

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	addr, err := mail.ParseAddress(email)
	// ParseAddress принимает и "Имя <a@b>", нам нужен только сам адрес
	if err != nil || addr.Address != email || len(email) > 254 {
		return "", domain.Invalid("email is invalid")
	}
	return email, nil
}
