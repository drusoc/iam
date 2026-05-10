package dto

import accountdomain "iam/internal/domain/account"

type GetCurrentSessionIn struct {
	SessionID string
}

type GetCurrentSessionOut struct {
	Account accountdomain.Account
}
