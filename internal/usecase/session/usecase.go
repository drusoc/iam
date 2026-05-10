package session

import (
	"context"
	"log/slog"
	"time"

	"iam/internal/apperror"
	accountdomain "iam/internal/domain/account"
	sessiondomain "iam/internal/domain/session"
	accountusecase "iam/internal/usecase/account"
	accountdto "iam/internal/usecase/account/dto"
	"iam/internal/usecase/session/dto"

	"github.com/go-faster/errors"
)

type Config struct {
	SessionTTL         time.Duration
	RefreshTTL         time.Duration
	RefreshAbsoluteTTL time.Duration
}

type usecase struct {
	config         Config
	sessionRepo    SessionRepository
	refreshRepo    RefreshSessionRepository
	accountUsecase AccountUsecase
}

func NewUsecase(
	config Config,
	sessionRepo SessionRepository,
	refreshRepo RefreshSessionRepository,
	accountUsecase AccountUsecase,
) Usecase {
	return &usecase{
		config:         config,
		sessionRepo:    sessionRepo,
		refreshRepo:    refreshRepo,
		accountUsecase: accountUsecase,
	}
}

func (u *usecase) GetCurrentSession(ctx context.Context, request dto.GetCurrentSessionIn) (*dto.GetCurrentSessionOut, error) {
	slog.Debug("get current session",
		slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
	)

	if request.SessionID == "" {
		slog.Warn("missing session id in get current session")
		return nil, apperror.MissingSession()
	}

	accountID, err := u.sessionRepo.Get(ctx, request.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, sessiondomain.ErrInvalidSession):
			slog.Warn("invalid session",
				slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
			)
			return nil, apperror.InvalidSession()
		case errors.Is(err, sessiondomain.ErrExpiredSession):
			slog.Debug("expired session",
				slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
			)
			return nil, apperror.ExpiredSession()
		default:
			slog.Error("load session",
				slog.Any("error", err),
				slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
			)
			return nil, apperror.Internal(errors.Wrap(err, "load session"))
		}
	}
	slog.Debug("session loaded",
		slog.Int64("account_id", accountID),
	)

	accountResponse, err := u.accountUsecase.GetByID(ctx, accountdto.GetByIDIn{ID: accountID})
	if err != nil {
		if errors.Is(err, accountdomain.ErrNotFound) {
			slog.Warn("account not found for session",
				slog.Int64("account_id", accountID),
				slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
			)
			return nil, apperror.ExpiredSession()
		}

		slog.Error("load account by session",
			slog.Any("error", err),
			slog.Int64("account_id", accountID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "load account by session"))
	}
	if accountResponse == nil {
		slog.Error("account response is nil",
			slog.Int64("account_id", accountID),
			slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
		)
		return nil, apperror.Internal(errors.New("account response is nil"))
	}

	if err = accountusecase.CanAuthenticate(accountResponse.Account); err != nil {
		switch {
		case errors.Is(err, accountdomain.ErrBlocked):
			slog.Warn("account blocked",
				slog.Int64("account_id", accountID),
				slog.String("email", accountResponse.Account.Email),
			)
			return nil, apperror.AccountBlocked()
		case errors.Is(err, accountdomain.ErrDeleted):
			slog.Warn("account deleted",
				slog.Int64("account_id", accountID),
				slog.String("email", accountResponse.Account.Email),
			)
			return nil, apperror.AccountDeleted()
		default:
			slog.Error("validate account status",
				slog.Any("error", err),
				slog.Int64("account_id", accountID),
			)
			return nil, apperror.Internal(errors.Wrap(err, "validate account status"))
		}
	}
	slog.Info("current session retrieved",
		slog.Int64("account_id", accountID),
		slog.String("email", accountResponse.Account.Email),
		slog.String("status", string(accountResponse.Account.Status)),
	)

	return &dto.GetCurrentSessionOut{Account: accountResponse.Account}, nil
}

func (u *usecase) Logout(ctx context.Context, request dto.LogoutIn) (*dto.LogoutOut, error) {
	slog.Debug("logout",
		slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
		slog.Bool("has_refresh_token", request.RefreshToken != ""),
	)

	if request.SessionID == "" && request.RefreshToken == "" {
		slog.Info("logout with empty session and token")
		return &dto.LogoutOut{}, nil
	}

	if request.SessionID != "" {
		err := u.sessionRepo.Delete(ctx, request.SessionID)
		if err != nil && !errors.Is(err, sessiondomain.ErrExpiredSession) && !errors.Is(err, sessiondomain.ErrInvalidSession) {
			slog.Error("delete session on logout",
				slog.Any("error", err),
				slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
			)
			return nil, apperror.Internal(errors.Wrap(err, "delete session"))
		}
		slog.Debug("session deleted on logout",
			slog.String("session_id", request.SessionID[:min(8, len(request.SessionID))]+"..."),
		)
	}

	if request.RefreshToken != "" {
		tokenHash := sessiondomain.HashToken(request.RefreshToken)
		refreshSession, err := u.refreshRepo.LoadByTokenHash(ctx, tokenHash)
		if err == nil {
			_ = u.refreshRepo.RevokeFamily(ctx, refreshSession.FamilyID)
			slog.Info("refresh family revoked on logout",
				slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
			)
		}
	}

	slog.Info("logout successful")
	return &dto.LogoutOut{}, nil
}

func (u *usecase) Refresh(ctx context.Context, request dto.RefreshIn) (*dto.RefreshOut, error) {
	slog.Debug("refresh session",
		slog.String("refresh_token", request.RefreshToken[:min(8, len(request.RefreshToken))]+"..."),
	)

	if request.RefreshToken == "" {
		slog.Warn("missing refresh token")
		return nil, apperror.MissingRefresh()
	}

	tokenHash := sessiondomain.HashToken(request.RefreshToken)
	refreshSession, err := u.refreshRepo.LoadByTokenHash(ctx, tokenHash)
	if err != nil {
		switch {
		case errors.Is(err, sessiondomain.ErrInvalidRefresh):
			slog.Warn("invalid refresh token")
			return nil, apperror.InvalidRefresh()
		case errors.Is(err, sessiondomain.ErrExpiredRefresh):
			slog.Warn("expired refresh token")
			return nil, apperror.ExpiredRefresh()
		default:
			slog.Error("load refresh session",
				slog.Any("error", err),
				slog.String("token_hash", tokenHash[:min(8, len(tokenHash))]+"..."),
			)
			return nil, apperror.Internal(errors.Wrap(err, "load refresh session"))
		}
	}
	slog.Debug("refresh session loaded",
		slog.Int64("account_id", refreshSession.AccountID),
		slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
	)

	now := time.Now()
	if refreshSession.IsUsed() {
		_ = u.refreshRepo.RevokeFamily(ctx, refreshSession.FamilyID)
		slog.Warn("refresh token reused - revoked",
			slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
		)
		return nil, apperror.RefreshReused()
	}
	if refreshSession.IsRevoked() {
		_ = u.refreshRepo.RevokeFamily(ctx, refreshSession.FamilyID)
		slog.Warn("refresh token revoked",
			slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
		)
		return nil, apperror.RefreshReused()
	}
	if refreshSession.IsExpired(now) {
		slog.Debug("refresh token expired",
			slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
		)
		return nil, apperror.ExpiredRefresh()
	}
	if refreshSession.IsAbsoluteExpired(now) {
		slog.Debug("refresh token absolute expired",
			slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
		)
		return nil, apperror.ExpiredRefresh()
	}

	accountResponse, err := u.accountUsecase.GetByID(ctx, accountdto.GetByIDIn{ID: refreshSession.AccountID})
	if err != nil {
		if errors.Is(err, accountdomain.ErrNotFound) {
			_ = u.refreshRepo.RevokeFamily(ctx, refreshSession.FamilyID)
			slog.Warn("account not found for refresh - revoked family",
				slog.Int64("account_id", refreshSession.AccountID),
			)
			return nil, apperror.ExpiredRefresh()
		}
		slog.Error("load account by refresh",
			slog.Any("error", err),
			slog.Int64("account_id", refreshSession.AccountID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "load account by refresh"))
	}
	if accountResponse == nil {
		slog.Error("account response is nil for refresh",
			slog.Int64("account_id", refreshSession.AccountID),
		)
		return nil, apperror.Internal(errors.New("account response is nil"))
	}

	if err = accountusecase.CanAuthenticate(accountResponse.Account); err != nil {
		switch {
		case errors.Is(err, accountdomain.ErrBlocked):
			slog.Warn("account blocked for refresh",
				slog.Int64("account_id", refreshSession.AccountID),
				slog.String("email", accountResponse.Account.Email),
			)
			return nil, apperror.AccountBlocked()
		case errors.Is(err, accountdomain.ErrDeleted):
			slog.Warn("account deleted for refresh",
				slog.Int64("account_id", refreshSession.AccountID),
				slog.String("email", accountResponse.Account.Email),
			)
			return nil, apperror.AccountDeleted()
		default:
			slog.Error("validate account status for refresh",
				slog.Any("error", err),
				slog.Int64("account_id", refreshSession.AccountID),
			)
			return nil, apperror.Internal(errors.Wrap(err, "validate account status for refresh"))
		}
	}

	_ = u.refreshRepo.MarkUsed(ctx, refreshSession.ID)

	newSessionID, err := u.sessionRepo.Create(ctx, refreshSession.AccountID, u.config.SessionTTL)
	if err != nil {
		slog.Error("create working session during refresh",
			slog.Any("error", err),
			slog.Int64("account_id", refreshSession.AccountID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "create working session during refresh"))
	}
	slog.Debug("new session created for refresh",
		slog.String("session_id", newSessionID[:min(8, len(newSessionID))]+"..."),
		slog.Int64("account_id", refreshSession.AccountID),
	)

	newRefreshToken, err := u.refreshRepo.Create(ctx, sessiondomain.RefreshSession{
		AccountID:         refreshSession.AccountID,
		FamilyID:          refreshSession.FamilyID,
		ParentID:          refreshSession.ID,
		ExpiresAt:         now.Add(u.config.RefreshTTL),
		AbsoluteExpiresAt: now.Add(u.config.RefreshAbsoluteTTL),
		IP:                refreshSession.IP,
		UserAgent:         refreshSession.UserAgent,
	})
	if err != nil {
		slog.Error("rotate refresh token",
			slog.Any("error", err),
			slog.Int64("account_id", refreshSession.AccountID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "rotate refresh token"))
	}
	slog.Debug("refresh token rotated",
		slog.String("family_id", refreshSession.FamilyID[:min(8, len(refreshSession.FamilyID))]+"..."),
		slog.Int64("account_id", refreshSession.AccountID),
	)

	slog.Info("session refreshed",
		slog.Int64("account_id", refreshSession.AccountID),
		slog.String("email", accountResponse.Account.Email),
		slog.String("session_id", newSessionID[:min(8, len(newSessionID))]+"..."),
	)

	return &dto.RefreshOut{
		SessionID:    newSessionID,
		RefreshToken: newRefreshToken,
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
