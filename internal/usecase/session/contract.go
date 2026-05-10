package session

import (
	"context"
	"time"

	sessiondomain "iam/internal/domain/session"
	accountdto "iam/internal/usecase/account/dto"
	"iam/internal/usecase/session/dto"
)

//go:generate mocks -source=$GOFILE -destination=mocks/contract.go -package mocks

type Usecase interface {
	GetCurrentSession(ctx context.Context, request dto.GetCurrentSessionIn) (*dto.GetCurrentSessionOut, error)
	Logout(ctx context.Context, request dto.LogoutIn) (*dto.LogoutOut, error)
	Refresh(ctx context.Context, request dto.RefreshIn) (*dto.RefreshOut, error)
}

type SessionRepository interface {
	Get(ctx context.Context, sessionID string) (int64, error)
	Delete(ctx context.Context, sessionID string) error
	Create(ctx context.Context, accountID int64, ttl time.Duration) (string, error)
}

type RefreshSessionRepository interface {
	Create(ctx context.Context, session sessiondomain.RefreshSession) (string, error)
	LoadByTokenHash(ctx context.Context, tokenHash string) (*sessiondomain.RefreshSession, error)
	MarkUsed(ctx context.Context, sessionID string) error
	Revoke(ctx context.Context, sessionID string) error
	RevokeFamily(ctx context.Context, familyID string) error
}

type AccountUsecase interface {
	GetByID(ctx context.Context, request accountdto.GetByIDIn) (*accountdto.GetByIDOut, error)
}
