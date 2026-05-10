package dto

import domain "iam/internal/domain/account"

type GetBuyIdentityIn struct {
	Identity domain.GoogleIdentity
}

type GetBuyIdentityOut struct {
	Account domain.Account
}
