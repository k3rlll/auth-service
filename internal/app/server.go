// Package app собирает HTTP-сервер: middleware, маршруты, служебные эндпоинты.
package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"auth/internal/security"
	httpapi "auth/internal/transport/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Максимальный размер тела запроса: запросам авторизации много не нужно
const bodyLimit = "64K"

type Deps struct {
	Logger     *slog.Logger
	Service    httpapi.AuthService
	Tokens     *security.TokenIssuer
	Limiter    *httpapi.IPRateLimiter
	Ready      func(ctx context.Context) error
	TrustProxy bool
}

func NewServer(d Deps) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = httpapi.ErrorHandler(d.Logger)

	// Без доверенного прокси IP берется только из адреса соединения:
	// X-Forwarded-For клиент может подставить сам
	if d.TrustProxy {
		e.IPExtractor = echo.ExtractIPFromXFFHeader()
	} else {
		e.IPExtractor = echo.ExtractIPDirect()
	}

	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.BodyLimit(bodyLimit))
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURIPath: true, LogStatus: true, LogLatency: true, LogMethod: true, LogRemoteIP: true,
		LogRequestID: true, HandleError: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			level := slog.LevelInfo
			switch {
			case v.Status >= 500:
				level = slog.LevelError
			case v.Status >= 400:
				level = slog.LevelWarn
			}
			d.Logger.Log(c.Request().Context(), level, "http request",
				"request_id", v.RequestID, "method", v.Method, "path", v.URIPath,
				"status", v.Status, "latency", v.Latency, "remote_ip", v.RemoteIP)
			return nil
		},
	}))

	h := httpapi.NewHandler(d.Service)
	auth := httpapi.RequireAuth(d.Service)

	v1 := e.Group("/api/v1")

	// Публичные эндпоинты, ограниченные по IP: защита от перебора и массовой регистрации
	public := v1.Group("/auth", d.Limiter.Middleware())
	public.POST("/register", h.Register)
	public.POST("/login", h.Login)
	public.POST("/refresh", h.Refresh)

	v1.POST("/auth/logout", h.Logout, auth)
	v1.GET("/users/me", h.Me, auth)
	v1.PUT("/users/me/password", h.ChangePassword, auth)

	sessions := v1.Group("/sessions", auth)
	sessions.GET("", h.ListSessions)
	sessions.DELETE("", h.RevokeOtherSessions)
	sessions.DELETE("/:id", h.RevokeSession)

	// Публичные ключи для проверки access-токенов другими сервисами
	e.GET("/.well-known/jwks.json", func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "public, max-age=300")
		return c.JSON(http.StatusOK, d.Tokens.JWKS())
	})

	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.GET("/readyz", func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
		defer cancel()
		if err := d.Ready(ctx); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	return e
}
