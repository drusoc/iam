package account

import (
	"context"
	domain "iam/internal/domain/account"
	"iam/internal/usecase/account/dto"
)

//go:generate mocks -source=$GOFILE -destination=mocks/contract.go -package mocks

type Usecase interface {
	GetBuyIdentity(ctx context.Context, request dto.GetBuyIdentityIn) (*dto.GetBuyIdentityOut, error)
	GetByID(ctx context.Context, request dto.GetByIDIn) (*dto.GetByIDOut, error)
}

type Repository interface {
	Create(ctx context.Context, identity domain.GoogleIdentity) (domain.Account, error)
	FindByGoogleSub(ctx context.Context, googleSub string) (domain.Account, error)
	FindByID(ctx context.Context, id int64) (domain.Account, error)
}
