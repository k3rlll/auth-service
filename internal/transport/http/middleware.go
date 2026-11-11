package http

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"auth/internal/domain"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

const (
	userIDKey    = "user_id"
	sessionIDKey = "session_id"
)

type Authenticator interface {
	Authenticate(ctx context.Context, accessToken string) (userID, sessionID string, err error)
}

// RequireAuth пропускает запрос только с действующим access-токеном,
// сессия которого не завершена
func RequireAuth(auth Authenticator) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			header := c.Request().Header.Get(echo.HeaderAuthorization)
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || token == "" {
				return domain.ErrUnauthorized
			}

			userID, sessionID, err := auth.Authenticate(c.Request().Context(), token)
			if err != nil {
				return err
			}

			c.Set(userIDKey, userID)
			c.Set(sessionIDKey, sessionID)
			return next(c)
		}
	}
}

func currentUser(c echo.Context) (userID, sessionID string) {
	userID, _ = c.Get(userIDKey).(string)
	sessionID, _ = c.Get(sessionIDKey).(string)
	return userID, sessionID
}

// IPRateLimiter ограничивает частоту запросов с одного IP (token bucket).
//
// Состояние хранится в памяти экземпляра: при нескольких экземплярах лимит
// действует на каждом отдельно. От перебора паролей конкретного аккаунта
// дополнительно защищает блокировка после серии неудачных входов, она общая (в БД).
type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	limit    rate.Limit
	burst    int
}

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewIPRateLimiter(perMinute, burst int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*ipLimiter),
		limit:    rate.Limit(float64(perMinute) / 60),
		burst:    burst,
	}
}

func (l *IPRateLimiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	entry, ok := l.limiters[ip]
	if !ok {
		entry = &ipLimiter{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	l.mu.Unlock()

	reservation := entry.limiter.Reserve()
	if delay := reservation.Delay(); delay > 0 {
		reservation.Cancel()
		return false, delay
	}
	return true, 0
}

// Cleanup удаляет давно не появлявшиеся IP, чтобы карта не росла бесконечно
func (l *IPRateLimiter) Cleanup(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, entry := range l.limiters {
		if time.Since(entry.lastSeen) > idle {
			delete(l.limiters, ip)
		}
	}
}

// RunCleanup чистит карту периодически, пока не отменен контекст
func (l *IPRateLimiter) RunCleanup(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Cleanup(every)
		}
	}
}

func (l *IPRateLimiter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if ok, wait := l.Allow(c.RealIP()); !ok {
				e := newAPIError(http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, slow down")
				e.header = map[string]string{"Retry-After": retryAfter(wait)}
				return e
			}
			return next(c)
		}
	}
}
