package domain

import "time"

// User - учетная запись. ID - ULID: его же получают другие сервисы в claim sub.
type User struct {
	ID           string
	Email        string // всегда в нижнем регистре
	Username     string
	PasswordHash string
	// Неудачные попытки входа подряд. Сбрасываются при успешном входе и при блокировке.
	FailedLogins int
	LockedUntil  *time.Time
	// После смены пароля прежние access-токены остаются валидными до истечения,
	// но все остальные сессии завершаются
	PasswordChangedAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// IsLocked сообщает, заблокирован ли вход на момент now
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

// Типы устройств
const (
	DevicePhone   = "phone"
	DeviceTablet  = "tablet"
	DeviceDesktop = "desktop"
	DeviceLaptop  = "laptop"
	DeviceWeb     = "web"
	DeviceOther   = "other"
)

// Причины завершения сессии
const (
	RevokeLogout         = "logout"
	RevokeByUser         = "revoked_by_user" // завершена с другого устройства
	RevokeLogoutOthers   = "logout_other_devices"
	RevokePasswordChange = "password_changed"
	RevokeTokenReuse     = "refresh_token_reuse" // признак кражи refresh-токена
	RevokeSessionLimit   = "session_limit"
)

// Session - вход с конкретного устройства. У каждого устройства своя сессия
// и свой refresh-токен, поэтому их можно видеть и завершать по отдельности.
type Session struct {
	ID         string
	UserID     string
	DeviceName string
	DeviceType string
	UserAgent  string
	IP         string
	CreatedAt  time.Time
	LastUsedAt time.Time
	// Скользящий срок: каждое обновление токенов продлевает сессию
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	RevokeReason string
}

// IsActive сообщает, действует ли сессия на момент now
func (s *Session) IsActive(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// RefreshToken - одноразовый токен обновления. В БД хранится только SHA-256 хэш:
// утечка базы не дает рабочих токенов. Каждое обновление выдает новый токен,
// а старый помечается использованным.
type RefreshToken struct {
	Hash      []byte
	SessionID string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}
