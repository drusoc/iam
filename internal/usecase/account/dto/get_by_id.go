package dto

import domain "iam/internal/domain/account"

type GetByIDIn struct {
	ID int64
}

type GetByIDOut struct {
	Account domain.Account
}
