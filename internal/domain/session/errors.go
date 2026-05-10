package session

import "errors"

var (
	ErrMissingSession   = errors.New("session is missing")
	ErrInvalidSession   = errors.New("session is invalid")
	ErrExpiredSession   = errors.New("session is expired")
	ErrMissingRefresh   = errors.New("refresh session is missing")
	ErrInvalidRefresh   = errors.New("refresh session is invalid")
	ErrExpiredRefresh   = errors.New("refresh session is expired")
	ErrUsedRefresh      = errors.New("refresh session already used")
	ErrRevokedRefresh   = errors.New("refresh session is revoked")
	ErrFamilyRevoked    = errors.New("refresh family is revoked")
	ErrInvalidTokenHash = errors.New("token hash is invalid")
)
