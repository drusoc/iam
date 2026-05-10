package oauth

import (
	"context"
	"time"

	accountdomain "iam/internal/domain/account"
	sessiondomain "iam/internal/domain/session"
	accountdto "iam/internal/usecase/account/dto"
	"iam/internal/usecase/oauth/dto"
)

//go:generate mocks -source=$GOFILE -destination=mocks/contract.go -package mocks

type Usecase interface {
	StartGoogleAuth(ctx context.Context, request dto.StartGoogleAuthIn) (*dto.StartGoogleAuthOut, error)
	HandleGoogleCallback(ctx context.Context, request dto.HandleGoogleCallbackIn) (*dto.HandleGoogleCallbackOut, error)
	ExchangeAuthCode(ctx context.Context, request dto.ExchangeAuthCodeIn) (*dto.ExchangeAuthCodeOut, error)
}

type StateRepository interface {
	Generate(ctx context.Context, ttl time.Duration) (string, error)
	Consume(ctx context.Context, state string) error
}

type GoogleProvider interface {
	ExchangeCode(ctx context.Context, code string) (accountdomain.GoogleIdentity, error)
}

type AccountUsecase interface {
	GetBuyIdentity(ctx context.Context, request accountdto.GetBuyIdentityIn) (*accountdto.GetBuyIdentityOut, error)
}

type AuthCodeRepository interface {
	Generate(ctx context.Context, accountID int64, ttl time.Duration) (string, error)
	Consume(ctx context.Context, code string) (int64, error)
}

type SessionRepository interface {
	Create(ctx context.Context, accountID int64, ttl time.Duration) (string, error)
}

type RefreshSessionRepository interface {
	Create(ctx context.Context, session sessiondomain.RefreshSession) (string, error)
}
