package account

import (
	"context"
	"errors"
	"log/slog"

	domain "iam/internal/domain/account"
	"iam/internal/usecase/account/dto"

	fasterrors "github.com/go-faster/errors"
)

type usecase struct {
	repository Repository
}

func NewUsecase(repository Repository) Usecase {
	return &usecase{repository: repository}
}

func (u *usecase) GetBuyIdentity(ctx context.Context, request dto.GetBuyIdentityIn) (*dto.GetBuyIdentityOut, error) {
	slog.Debug("get or create account by identity",
		slog.String("google_sub", request.Identity.Sub),
		slog.String("email", request.Identity.Email),
	)

	identity := request.Identity
	if !identity.EmailVerified {
		slog.Warn("email not verified",
			slog.String("google_sub", identity.Sub),
			slog.String("email", identity.Email),
		)
		return nil, domain.ErrEmailUnverified
	}

	account, err := u.repository.FindByGoogleSub(ctx, identity.Sub)
	if errors.Is(err, domain.ErrNotFound) {
		slog.Info("account not found, creating new",
			slog.String("google_sub", identity.Sub),
			slog.String("email", identity.Email),
		)
		account, err = u.repository.Create(ctx, identity)
	}
	if err != nil {
		slog.Error("load or create account by google identity",
			slog.Any("error", err),
			slog.String("google_sub", identity.Sub),
			slog.String("email", identity.Email),
		)
		return nil, fasterrors.Wrap(err, "load or create account by google identity")
	}

	if err = CanAuthenticate(account); err != nil {
		slog.Warn("account cannot authenticate",
			slog.Any("error", err),
			slog.Int64("account_id", account.ID),
			slog.String("status", string(account.Status)),
		)
		return nil, err
	}
	slog.Info("account authenticated by identity",
		slog.Int64("account_id", account.ID),
		slog.String("email", account.Email),
		slog.String("status", string(account.Status)),
	)

	return &dto.GetBuyIdentityOut{Account: account}, nil
}

func (u *usecase) GetByID(ctx context.Context, request dto.GetByIDIn) (*dto.GetByIDOut, error) {
	slog.Debug("get account by id",
		slog.Int64("account_id", request.ID),
	)
	account, err := u.repository.FindByID(ctx, request.ID)
	if err != nil {
		slog.Error("find account by id",
			slog.Any("error", err),
			slog.Int64("account_id", request.ID),
		)
		return nil, fasterrors.Wrap(err, "find account by id")
	}
	slog.Debug("account found by id",
		slog.Int64("account_id", account.ID),
		slog.String("email", account.Email),
		slog.String("status", string(account.Status)),
	)

	return &dto.GetByIDOut{Account: account}, nil
}

func CanAuthenticate(account domain.Account) error {
	switch account.Status {
	case domain.StatusActive:
		return nil
	case domain.StatusBlocked:
		return domain.ErrBlocked
	case domain.StatusDeleted:
		return domain.ErrDeleted
	default:
		return domain.ErrBlocked
	}
}
