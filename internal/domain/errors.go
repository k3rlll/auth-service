package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrEmailTaken         = errors.New("email is already registered")
	ErrUsernameTaken      = errors.New("username is already taken")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidRefresh     = errors.New("refresh token is invalid or expired")
	ErrRefreshReused      = errors.New("refresh token was already used")
	ErrRefreshConflict    = errors.New("refresh token was just rotated")
	ErrNotFound           = errors.New("not found")
	ErrRateLimited        = errors.New("too many requests")
	ErrInternal           = errors.New("internal error")

	// ErrDuplicate возвращает хранилище при нарушении уникальности.
	// Наружу не уходит: usecase превращает его в осмысленную ошибку.
	ErrDuplicate = errors.New("duplicate key")
)

// DetailedError - ошибка известного вида с сообщением, которое безопасно показать клиенту
type DetailedError struct {
	Kind    error
	Message string
}

func (e *DetailedError) Error() string { return e.Message }
func (e *DetailedError) Unwrap() error { return e.Kind }

func Invalid(message string) error { return &DetailedError{Kind: ErrInvalidInput, Message: message} }

// LockedError - вход временно заблокирован после серии неудачных попыток
type LockedError struct {
	Until time.Time
}

func (e *LockedError) Error() string { return "account is temporarily locked" }
