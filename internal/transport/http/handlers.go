// Package http - HTTP API сервиса авторизации.
package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"auth/internal/domain"
	"auth/internal/usecase"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type AuthService interface {
	Authenticator
	Register(ctx context.Context, p usecase.RegisterParams) (*usecase.AuthResult, error)
	Login(ctx context.Context, email, password string, device usecase.Device) (*usecase.AuthResult, error)
	Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResult, error)
	Logout(ctx context.Context, userID, sessionID string) error
	GetUser(ctx context.Context, userID string) (*domain.User, error)
	ChangePassword(ctx context.Context, userID, sessionID, oldPassword, newPassword string) error
	ListSessions(ctx context.Context, userID, currentSessionID string) ([]usecase.SessionView, error)
	RevokeSession(ctx context.Context, userID, currentSessionID, targetSessionID string) error
	RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) (int64, error)
}

type Handler struct {
	svc AuthService
}

func NewHandler(svc AuthService) *Handler {
	return &Handler{svc: svc}
}

// --- DTO ---

type DeviceDTO struct {
	Name string `json:"name" validate:"max=100"`
	// phone, tablet, desktop, laptop, web, other. Пустое - определится по User-Agent
	Type string `json:"type" validate:"omitempty,oneof=phone tablet desktop laptop web other"`
}

type RegisterRequest struct {
	Email    string    `json:"email" validate:"required,max=254"`
	Username string    `json:"username" validate:"required,max=32"`
	Password string    `json:"password" validate:"required,max=128"`
	Device   DeviceDTO `json:"device"`
}

type LoginRequest struct {
	Email    string    `json:"email" validate:"required,max=254"`
	Password string    `json:"password" validate:"required,max=128"`
	Device   DeviceDTO `json:"device"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=128"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=128"`
	NewPassword     string `json:"new_password" validate:"required,max=128"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

type SessionResponse struct {
	ID         string    `json:"id"`
	DeviceName string    `json:"device_name"`
	DeviceType string    `json:"device_type"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
}

type TokensResponse struct {
	TokenType        string           `json:"token_type"`
	AccessToken      string           `json:"access_token"`
	ExpiresIn        int64            `json:"expires_in"` // секунд до истечения access-токена
	AccessExpiresAt  time.Time        `json:"access_expires_at"`
	RefreshToken     string           `json:"refresh_token"`
	RefreshExpiresAt time.Time        `json:"refresh_expires_at"`
	Session          *SessionResponse `json:"session"`
	User             *UserResponse    `json:"user,omitempty"`
}

func toUser(u *domain.User) *UserResponse {
	return &UserResponse{ID: u.ID, Email: u.Email, Username: u.Username, CreatedAt: u.CreatedAt}
}

func toSession(s *domain.Session, current bool) *SessionResponse {
	return &SessionResponse{
		ID: s.ID, DeviceName: s.DeviceName, DeviceType: s.DeviceType, IP: s.IP, UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt, LastUsedAt: s.LastUsedAt, ExpiresAt: s.ExpiresAt, Current: current,
	}
}

func toTokens(r *usecase.AuthResult) TokensResponse {
	resp := TokensResponse{
		TokenType:        "Bearer",
		AccessToken:      r.Tokens.AccessToken,
		ExpiresIn:        int64(time.Until(r.Tokens.AccessExpiresAt).Round(time.Second).Seconds()),
		AccessExpiresAt:  r.Tokens.AccessExpiresAt,
		RefreshToken:     r.Tokens.RefreshToken,
		RefreshExpiresAt: r.Tokens.RefreshExpiresAt,
		Session:          toSession(r.Session, true),
	}
	if r.User != nil {
		resp.User = toUser(r.User)
	}
	return resp
}

func device(c echo.Context, d DeviceDTO) usecase.Device {
	return usecase.Device{
		Name:      d.Name,
		Type:      d.Type,
		UserAgent: c.Request().UserAgent(),
		IP:        c.RealIP(),
	}
}

// --- Хендлеры ---

// Register - POST /api/v1/auth/register
func (h *Handler) Register(c echo.Context) error {
	var req RegisterRequest
	if err := bind(c, &req); err != nil {
		return err
	}

	result, err := h.svc.Register(c.Request().Context(), usecase.RegisterParams{
		Email: req.Email, Username: req.Username, Password: req.Password, Device: device(c, req.Device),
	})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, toTokens(result))
}

// Login - POST /api/v1/auth/login
func (h *Handler) Login(c echo.Context) error {
	var req LoginRequest
	if err := bind(c, &req); err != nil {
		return err
	}

	result, err := h.svc.Login(c.Request().Context(), req.Email, req.Password, device(c, req.Device))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, toTokens(result))
}

// Refresh - POST /api/v1/auth/refresh
func (h *Handler) Refresh(c echo.Context) error {
	var req RefreshRequest
	if err := bind(c, &req); err != nil {
		return err
	}

	result, err := h.svc.Refresh(c.Request().Context(), req.RefreshToken)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, toTokens(result))
}

// Logout завершает текущую сессию - POST /api/v1/auth/logout
func (h *Handler) Logout(c echo.Context) error {
	userID, sessionID := currentUser(c)
	if err := h.svc.Logout(c.Request().Context(), userID, sessionID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// Me - GET /api/v1/users/me
func (h *Handler) Me(c echo.Context) error {
	userID, _ := currentUser(c)
	user, err := h.svc.GetUser(c.Request().Context(), userID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, toUser(user))
}

// ChangePassword - PUT /api/v1/users/me/password. Завершает все остальные сессии.
func (h *Handler) ChangePassword(c echo.Context) error {
	var req ChangePasswordRequest
	if err := bind(c, &req); err != nil {
		return err
	}

	userID, sessionID := currentUser(c)
	if err := h.svc.ChangePassword(c.Request().Context(), userID, sessionID, req.CurrentPassword, req.NewPassword); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ListSessions - устройства пользователя. GET /api/v1/sessions
func (h *Handler) ListSessions(c echo.Context) error {
	userID, sessionID := currentUser(c)
	sessions, err := h.svc.ListSessions(c.Request().Context(), userID, sessionID)
	if err != nil {
		return err
	}

	resp := make([]*SessionResponse, len(sessions))
	for i := range sessions {
		resp[i] = toSession(&sessions[i].Session, sessions[i].Current)
	}
	return c.JSON(http.StatusOK, map[string]any{"sessions": resp})
}

// RevokeSession - выход на конкретном устройстве. DELETE /api/v1/sessions/:id
func (h *Handler) RevokeSession(c echo.Context) error {
	userID, sessionID := currentUser(c)
	if err := h.svc.RevokeSession(c.Request().Context(), userID, sessionID, c.Param("id")); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// RevokeOtherSessions - выход на всех устройствах, кроме текущего. DELETE /api/v1/sessions
func (h *Handler) RevokeOtherSessions(c echo.Context) error {
	userID, sessionID := currentUser(c)
	n, err := h.svc.RevokeOtherSessions(c.Request().Context(), userID, sessionID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]int64{"revoked": n})
}

// --- Разбор запросов ---

var validate = validator.New()

func bind(c echo.Context, req any) error {
	if err := c.Bind(req); err != nil {
		return newAPIError(http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
	}

	if err := validate.Struct(req); err != nil {
		var verrs validator.ValidationErrors
		if errors.As(err, &verrs) {
			e := newAPIError(http.StatusUnprocessableEntity, "VALIDATION_ERROR", "validation failed")
			e.details = make(map[string]string, len(verrs))
			for _, f := range verrs {
				e.details[f.Namespace()] = fmt.Sprintf("failed on the '%s' rule", f.Tag())
			}
			return e
		}
		return newAPIError(http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
	}
	return nil
}
