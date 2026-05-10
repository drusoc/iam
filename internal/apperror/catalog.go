package apperror

import (
	accountdomain "iam/internal/domain/account"
	domain "iam/internal/domain/oauth"
	sessiondomain "iam/internal/domain/session"
	"net/http"
)

func BadRequest(code, message string, cause error) *Error {
	return New(http.StatusBadRequest, code, message, cause)
}

func Unauthorized(code, message string, cause error) *Error {
	return New(http.StatusUnauthorized, code, message, cause)
}

func Forbidden(code, message string, cause error) *Error {
	return New(http.StatusForbidden, code, message, cause)
}

func Internal(cause error) *Error {
	return New(
		http.StatusInternalServerError,
		"internal-error",
		"Внутренняя ошибка сервиса",
		cause,
	)
}

func InvalidRequestBody(cause error) *Error {
	return BadRequest(
		"bad-request",
		"Некорректное тело запроса",
		cause,
	)
}

func MissingCode() *Error {
	return BadRequest(
		"missing-code",
		"Отсутствует параметр code",
		domain.ErrMissingCode,
	)
}

func MissingState() *Error {
	return BadRequest(
		"missing-state",
		"Отсутствует параметр state",
		domain.ErrMissingState,
	)
}

func InvalidState(cause error) *Error {
	return BadRequest(
		"invalid-state",
		"Некорректный параметр state",
		cause,
	)
}

func InvalidToken(cause error) *Error {
	return BadRequest(
		"invalid-token",
		"Не удалось проверить Google токен",
		cause,
	)
}

func MissingAuthCode() *Error {
	return BadRequest(
		"missing-auth-code",
		"Отсутствует код авторизации",
		domain.ErrMissingAuthCode,
	)
}

func InvalidAuthCode(cause error) *Error {
	return BadRequest(
		"invalid-auth-code",
		"Некорректный или истекший код авторизации",
		cause,
	)
}

func EmailUnverified() *Error {
	return BadRequest(
		"email-unverified",
		"Email в Google аккаунте не подтвержден",
		accountdomain.ErrEmailUnverified,
	)
}

func MissingSession() *Error {
	return Unauthorized(
		"missing-session",
		"Сессия не найдена",
		sessiondomain.ErrMissingSession,
	)
}

func InvalidSession() *Error {
	return Unauthorized(
		"invalid-session",
		"Некорректная сессия",
		sessiondomain.ErrInvalidSession,
	)
}

func ExpiredSession() *Error {
	return Unauthorized(
		"expired-session",
		"Сессия истекла",
		sessiondomain.ErrExpiredSession,
	)
}

func AccountBlocked() *Error {
	return Forbidden(
		"account-blocked",
		"Аккаунт заблокирован",
		accountdomain.ErrBlocked,
	)
}

func AccountDeleted() *Error {
	return Forbidden(
		"account-deleted",
		"Аккаунт удален",
		accountdomain.ErrDeleted,
	)
}

func MissingRefresh() *Error {
	return Unauthorized(
		"missing-refresh",
		"Refresh токен не найден",
		sessiondomain.ErrMissingRefresh,
	)
}

func InvalidRefresh() *Error {
	return Unauthorized(
		"invalid-refresh",
		"Некорректный refresh токен",
		sessiondomain.ErrInvalidRefresh,
	)
}

func ExpiredRefresh() *Error {
	return Unauthorized(
		"expired-refresh",
		"Refresh токен истек",
		sessiondomain.ErrExpiredRefresh,
	)
}

func RefreshReused() *Error {
	return Unauthorized(
		"refresh-reused",
		"Refresh токен уже использован — требуется повторный вход",
		sessiondomain.ErrUsedRefresh,
	)
}
