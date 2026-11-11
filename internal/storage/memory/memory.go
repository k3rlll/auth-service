// Package memory - хранилище в памяти для тестов.
//
// Повторяет семантику PostgreSQL-хранилища, включая транзакции: InTx выполняется
// под эксклюзивной блокировкой, а при ошибке все изменения откатываются.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"auth/internal/domain"
	"auth/internal/usecase"
)

type state struct {
	users    map[string]domain.User
	sessions map[string]domain.Session
	tokens   map[string]domain.RefreshToken // ключ - string(hash)
}

func (s *state) clone() *state {
	c := &state{
		users:    make(map[string]domain.User, len(s.users)),
		sessions: make(map[string]domain.Session, len(s.sessions)),
		tokens:   make(map[string]domain.RefreshToken, len(s.tokens)),
	}
	for k, v := range s.users {
		c.users[k] = v
	}
	for k, v := range s.sessions {
		c.sessions[k] = v
	}
	for k, v := range s.tokens {
		c.tokens[k] = v
	}
	return c
}

type Store struct {
	mu    *sync.Mutex
	state **state
	inTx  bool
}

var _ usecase.Store = (*Store)(nil)

func New() *Store {
	st := &state{
		users:    map[string]domain.User{},
		sessions: map[string]domain.Session{},
		tokens:   map[string]domain.RefreshToken{},
	}
	return &Store{mu: &sync.Mutex{}, state: &st}
}

// lock берет блокировку, если вызов не внутри транзакции (там она уже взята)
func (s *Store) lock() func() {
	if s.inTx {
		return func() {}
	}
	s.mu.Lock()
	return s.mu.Unlock
}

func (s *Store) InTx(_ context.Context, fn func(usecase.Store) error) error {
	if s.inTx {
		return fn(s)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := (*s.state).clone()
	if err := fn(&Store{mu: s.mu, state: s.state, inTx: true}); err != nil {
		*s.state = snapshot
		return err
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

func (s *Store) CreateUser(_ context.Context, u *domain.User) error {
	defer s.lock()()
	for _, existing := range (*s.state).users {
		if strings.EqualFold(existing.Email, u.Email) {
			return domain.ErrEmailTaken
		}
		if strings.EqualFold(existing.Username, u.Username) {
			return domain.ErrUsernameTaken
		}
	}
	(*s.state).users[u.ID] = *u
	return nil
}

func (s *Store) GetUserByID(_ context.Context, id string) (*domain.User, error) {
	defer s.lock()()
	u, ok := (*s.state).users[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &u, nil
}

func (s *Store) GetUserByEmail(_ context.Context, email string) (*domain.User, error) {
	defer s.lock()()
	for _, u := range (*s.state).users {
		if strings.EqualFold(u.Email, email) {
			return &u, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) RecordLoginFailure(_ context.Context, userID string, maxAttempts int, lockout time.Duration, now time.Time) (*time.Time, error) {
	defer s.lock()()
	u, ok := (*s.state).users[userID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if u.FailedLogins+1 >= maxAttempts {
		u.FailedLogins = 0
		u.LockedUntil = ptr(now.Add(lockout))
	} else {
		u.FailedLogins++
	}
	(*s.state).users[userID] = u

	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		return ptr(*u.LockedUntil), nil
	}
	return nil, nil
}

func (s *Store) ResetLoginFailures(_ context.Context, userID string) error {
	defer s.lock()()
	if u, ok := (*s.state).users[userID]; ok {
		u.FailedLogins, u.LockedUntil = 0, nil
		(*s.state).users[userID] = u
	}
	return nil
}

func (s *Store) UpdatePassword(_ context.Context, userID, hash string, now time.Time) error {
	defer s.lock()()
	u, ok := (*s.state).users[userID]
	if !ok {
		return domain.ErrNotFound
	}
	u.PasswordHash, u.PasswordChangedAt, u.UpdatedAt = hash, now, now
	(*s.state).users[userID] = u
	return nil
}

func (s *Store) CreateSession(_ context.Context, sess *domain.Session) error {
	defer s.lock()()
	(*s.state).sessions[sess.ID] = *sess
	return nil
}

func (s *Store) GetSession(_ context.Context, id string) (*domain.Session, error) {
	defer s.lock()()
	sess, ok := (*s.state).sessions[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &sess, nil
}

func (s *Store) ListActiveSessions(_ context.Context, userID string, now time.Time) ([]domain.Session, error) {
	defer s.lock()()
	out := []domain.Session{}
	for _, sess := range (*s.state).sessions {
		if sess.UserID == userID && sess.IsActive(now) {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastUsedAt.Equal(out[j].LastUsedAt) {
			return out[i].LastUsedAt.After(out[j].LastUsedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (s *Store) TouchSession(_ context.Context, id string, lastUsed, expiresAt time.Time) error {
	defer s.lock()()
	if sess, ok := (*s.state).sessions[id]; ok {
		sess.LastUsedAt, sess.ExpiresAt = lastUsed, expiresAt
		(*s.state).sessions[id] = sess
	}
	return nil
}

func (s *Store) RevokeSession(_ context.Context, userID, sessionID, reason string, now time.Time) (bool, error) {
	defer s.lock()()
	sess, ok := (*s.state).sessions[sessionID]
	if !ok || sess.UserID != userID || sess.RevokedAt != nil {
		return false, nil
	}
	sess.RevokedAt, sess.RevokeReason = ptr(now), reason
	(*s.state).sessions[sessionID] = sess
	return true, nil
}

func (s *Store) RevokeUserSessions(_ context.Context, userID, exceptID, reason string, now time.Time) (int64, error) {
	defer s.lock()()
	var n int64
	for id, sess := range (*s.state).sessions {
		if sess.UserID == userID && id != exceptID && sess.RevokedAt == nil {
			sess.RevokedAt, sess.RevokeReason = ptr(now), reason
			(*s.state).sessions[id] = sess
			n++
		}
	}
	return n, nil
}

func (s *Store) CreateRefreshToken(_ context.Context, t *domain.RefreshToken) error {
	defer s.lock()()
	(*s.state).tokens[string(t.Hash)] = *t
	return nil
}

func (s *Store) GetRefreshTokenForUpdate(_ context.Context, hash []byte) (*domain.RefreshToken, error) {
	defer s.lock()()
	t, ok := (*s.state).tokens[string(hash)]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &t, nil
}

func (s *Store) MarkRefreshTokenUsed(_ context.Context, hash []byte, now time.Time) error {
	defer s.lock()()
	if t, ok := (*s.state).tokens[string(hash)]; ok {
		t.UsedAt = ptr(now)
		(*s.state).tokens[string(hash)] = t
	}
	return nil
}

func (s *Store) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	defer s.lock()()
	var n int64
	for k, t := range (*s.state).tokens {
		if t.ExpiresAt.Before(now) {
			delete((*s.state).tokens, k)
			n++
		}
	}
	cutoff := now.Add(-30 * 24 * time.Hour)
	for id, sess := range (*s.state).sessions {
		if (sess.RevokedAt != nil && sess.RevokedAt.Before(cutoff)) || sess.ExpiresAt.Before(cutoff) {
			delete((*s.state).sessions, id)
			n++
		}
	}
	return n, nil
}
