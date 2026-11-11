package http

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"auth/internal/domain"

	"github.com/labstack/echo/v4"
)

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// apiError - ошибка, готовая к отправке клиенту
type apiError struct {
	status  int
	code    string
	message string
	details map[string]string
	header  map[string]string
}

func (e *apiError) Error() string { return e.message }

func newAPIError(status int, code, message string) *apiError {
	return &apiError{status: status, code: code, message: message}
}

// mapError переводит доменную ошибку в ответ API. known == false - ошибка неожиданная.
func mapError(err error) (*apiError, bool) {
	var (
		api      *apiError
		detailed *domain.DetailedError
		locked   *domain.LockedError
	)

	switch {
	case errors.As(err, &api):
		return api, true
	case errors.As(err, &detailed):
		return newAPIError(http.StatusBadRequest, "INVALID_REQUEST", detailed.Message), true
	case errors.As(err, &locked):
		e := newAPIError(http.StatusTooManyRequests, "ACCOUNT_LOCKED",
			"too many failed login attempts, try again later")
		e.header = map[string]string{"Retry-After": retryAfter(time.Until(locked.Until))}
		return e, true
	case errors.Is(err, domain.ErrEmailTaken):
		return newAPIError(http.StatusConflict, "EMAIL_TAKEN", err.Error()), true
	case errors.Is(err, domain.ErrUsernameTaken):
		return newAPIError(http.StatusConflict, "USERNAME_TAKEN", err.Error()), true
	case errors.Is(err, domain.ErrInvalidCredentials):
		return newAPIError(http.StatusUnauthorized, "INVALID_CREDENTIALS", err.Error()), true
	case errors.Is(err, domain.ErrUnauthorized):
		return newAPIError(http.StatusUnauthorized, "UNAUTHORIZED", "access token is missing, invalid or its session has ended"), true
	case errors.Is(err, domain.ErrInvalidRefresh):
		return newAPIError(http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", err.Error()), true
	case errors.Is(err, domain.ErrRefreshReused):
		return newAPIError(http.StatusUnauthorized, "REFRESH_TOKEN_REUSED",
			"refresh token was already used; the session has been ended for safety, please log in again"), true
	case errors.Is(err, domain.ErrRefreshConflict):
		return newAPIError(http.StatusConflict, "REFRESH_CONFLICT",
			"this refresh token was just exchanged by another request; use the newest token"), true
	case errors.Is(err, domain.ErrNotFound):
		return newAPIError(http.StatusNotFound, "NOT_FOUND", "not found"), true
	case errors.Is(err, domain.ErrRateLimited):
		return newAPIError(http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, slow down"), true
	}
	return newAPIError(http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error"), false
}

// ErrorHandler - обработчик ошибок Echo: единый формат ответа и логирование неожиданных ошибок
func ErrorHandler(logger *slog.Logger) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		var api *apiError
		var he *echo.HTTPError
		switch {
		case errors.As(err, &he):
			// Ошибки самого Echo: 404 маршрута, 405, слишком большое тело и т.п.
			api = newAPIError(he.Code, codeForStatus(he.Code), fmt.Sprint(he.Message))
		default:
			var known bool
			api, known = mapError(err)
			if !known {
				logger.ErrorContext(c.Request().Context(), "request failed",
					"method", c.Request().Method, "path", c.Path(), "error", err)
			}
		}

		for k, v := range api.header {
			c.Response().Header().Set(k, v)
		}
		_ = c.JSON(api.status, ErrorResponse{Error: ErrorBody{Code: api.code, Message: api.message, Details: api.details}})
	}
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case http.StatusRequestEntityTooLarge:
		return "REQUEST_TOO_LARGE"
	case http.StatusBadRequest:
		return "INVALID_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	}
	return "INTERNAL_ERROR"
}

func retryAfter(d time.Duration) string {
	return strconv.Itoa(max(int(math.Ceil(d.Seconds())), 1))
}
