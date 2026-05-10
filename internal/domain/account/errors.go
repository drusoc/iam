package account

import "errors"

var (
	ErrNotFound        = errors.New("account not found")
	ErrEmailUnverified = errors.New("google email is not verified")
	ErrBlocked         = errors.New("account is blocked")
	ErrDeleted         = errors.New("account is deleted")
)
