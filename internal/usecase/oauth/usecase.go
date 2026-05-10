package oauth

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"iam/internal/apperror"
	accountdomain "iam/internal/domain/account"
	domain "iam/internal/domain/oauth"
	sessiondomain "iam/internal/domain/session"
	accountdto "iam/internal/usecase/account/dto"
	"iam/internal/usecase/oauth/dto"

	"github.com/go-faster/errors"
	"github.com/google/uuid"
)

type Config struct {
	ClientID           string
	AuthURL            string
	RedirectURL        string
	AppSuccessURL      string
	Scopes             []string
	StateTTL           time.Duration
	AuthCodeTTL        time.Duration
	SessionTTL         time.Duration
	RefreshTTL         time.Duration
	RefreshAbsoluteTTL time.Duration
}

type usecase struct {
	config         Config
	state          StateRepository
	authCode       AuthCodeRepository
	session        SessionRepository
	refreshSession RefreshSessionRepository
	google         GoogleProvider
	accountUsecase AccountUsecase
}

func NewUsecase(
	config Config,
	state StateRepository,
	authCode AuthCodeRepository,
	session SessionRepository,
	refreshSession RefreshSessionRepository,
	google GoogleProvider,
	accountUsecase AccountUsecase,
) Usecase {
	return &usecase{
		config:         config,
		state:          state,
		authCode:       authCode,
		session:        session,
		refreshSession: refreshSession,
		google:         google,
		accountUsecase: accountUsecase,
	}
}

func (u *usecase) StartGoogleAuth(ctx context.Context, _ dto.StartGoogleAuthIn) (*dto.StartGoogleAuthOut, error) {
	slog.Debug("start google auth",
		slog.Any("context", ctx),
	)

	state, err := u.state.Generate(ctx, u.config.StateTTL)
	if err != nil {
		slog.Error("generate oauth state",
			slog.Any("error", err),
		)
		return nil, apperror.Internal(errors.Wrap(err, "generate oauth state"))
	}
	slog.Debug("oauth state generated",
		slog.String("state", state[:8]+"..."),
		slog.Duration("ttl", u.config.StateTTL),
	)

	redirectURL, err := u.googleAuthURL(state)
	if err != nil {
		slog.Error("build google auth url",
			slog.Any("error", err),
		)
		return nil, apperror.Internal(errors.Wrap(err, "build google auth url"))
	}

	return &dto.StartGoogleAuthOut{
		RedirectURL: redirectURL,
		State:       state,
	}, nil
}

func (u *usecase) HandleGoogleCallback(ctx context.Context, request dto.HandleGoogleCallbackIn) (*dto.HandleGoogleCallbackOut, error) {
	slog.Debug("handle google callback",
		slog.String("state", request.State[:8]+"..."),
		slog.Bool("has_code", request.Code != ""),
	)

	if request.State == "" {
		slog.Warn("missing state in callback")
		return nil, apperror.MissingState()
	}
	if request.Code == "" {
		slog.Warn("missing code in callback")
		return nil, apperror.MissingCode()
	}

	if err := u.state.Consume(ctx, request.State); err != nil {
		slog.Error("consume oauth state",
			slog.Any("error", err),
			slog.String("state", request.State[:8]+"..."),
		)
		if errors.Is(err, domain.ErrInvalidState) {
			return nil, apperror.InvalidState(err)
		}

		return nil, apperror.Internal(errors.Wrap(err, "consume oauth state"))
	}
	slog.Debug("oauth state consumed",
		slog.String("state", request.State[:8]+"..."),
	)

	identity, err := u.google.ExchangeCode(ctx, request.Code)
	if err != nil {
		slog.Error("exchange google code",
			slog.Any("error", err),
		)
		if errors.Is(err, domain.ErrInvalidToken) {
			return nil, apperror.InvalidToken(err)
		}

		return nil, apperror.Internal(errors.Wrap(err, "exchange google code"))
	}
	slog.Info("google identity obtained",
		slog.String("sub", identity.Sub),
		slog.String("email", identity.Email),
	)

	account, err := u.accountUsecase.GetBuyIdentity(ctx, accountdto.GetBuyIdentityIn{Identity: identity})
	if err != nil {
		slog.Error("get or create account by identity",
			slog.Any("error", err),
			slog.String("google_sub", identity.Sub),
			slog.String("email", identity.Email),
		)
		switch {
		case errors.Is(err, accountdomain.ErrEmailUnverified):
			return nil, apperror.EmailUnverified()
		case errors.Is(err, accountdomain.ErrBlocked):
			return nil, apperror.AccountBlocked()
		case errors.Is(err, accountdomain.ErrDeleted):
			return nil, apperror.AccountDeleted()
		default:
			return nil, apperror.Internal(errors.Wrap(err, "authenticate google account"))
		}
	}
	slog.Info("account authorized",
		slog.Int64("account_id", account.Account.ID),
		slog.String("email", account.Account.Email),
		slog.String("status", string(account.Account.Status)),
	)

	authCode, err := u.authCode.Generate(ctx, account.Account.ID, u.config.AuthCodeTTL)
	if err != nil {
		slog.Error("generate auth code",
			slog.Any("error", err),
			slog.Int64("account_id", account.Account.ID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "generate auth code"))
	}
	slog.Debug("auth code generated",
		slog.String("code", authCode[:8]+"..."),
		slog.Int64("account_id", account.Account.ID),
	)

	successURL, err := withCode(u.config.AppSuccessURL, authCode)
	if err != nil {
		slog.Error("build app success redirect",
			slog.Any("error", err),
		)
		return nil, apperror.Internal(errors.Wrap(err, "build app success redirect"))
	}

	return &dto.HandleGoogleCallbackOut{RedirectURL: successURL}, nil
}

func (u *usecase) ExchangeAuthCode(ctx context.Context, request dto.ExchangeAuthCodeIn) (*dto.ExchangeAuthCodeOut, error) {
	slog.Debug("exchange auth code",
		slog.String("code", request.Code[:min(8, len(request.Code))]+"..."),
	)

	if request.Code == "" {
		slog.Warn("missing auth code")
		return nil, apperror.MissingAuthCode()
	}

	accountID, err := u.authCode.Consume(ctx, request.Code)
	if err != nil {
		slog.Error("consume auth code",
			slog.Any("error", err),
			slog.String("code", request.Code[:min(8, len(request.Code))]+"..."),
		)
		if errors.Is(err, domain.ErrInvalidAuthCode) {
			return nil, apperror.InvalidAuthCode(err)
		}

		return nil, apperror.Internal(errors.Wrap(err, "consume auth code"))
	}
	slog.Debug("auth code consumed",
		slog.Int64("account_id", accountID),
	)

	sessionID, err := u.session.Create(ctx, accountID, u.config.SessionTTL)
	if err != nil {
		slog.Error("create session",
			slog.Any("error", err),
			slog.Int64("account_id", accountID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "create session"))
	}
	slog.Debug("session created",
		slog.String("session_id", sessionID[:8]+"..."),
		slog.Int64("account_id", accountID),
	)

	now := time.Now()
	familyID := uuid.NewString()

	refreshToken, err := u.refreshSession.Create(ctx, sessiondomain.RefreshSession{
		AccountID:         accountID,
		FamilyID:          familyID,
		ParentID:          "",
		ExpiresAt:         now.Add(u.config.RefreshTTL),
		AbsoluteExpiresAt: now.Add(u.config.RefreshAbsoluteTTL),
	})
	if err != nil {
		slog.Error("create refresh session",
			slog.Any("error", err),
			slog.Int64("account_id", accountID),
		)
		return nil, apperror.Internal(errors.Wrap(err, "create refresh session"))
	}
	slog.Debug("refresh session created",
		slog.String("family_id", familyID[:8]+"..."),
		slog.Int64("account_id", accountID),
	)

	return &dto.ExchangeAuthCodeOut{
		SessionID:    sessionID,
		RefreshToken: refreshToken,
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (u *usecase) googleAuthURL(state string) (string, error) {
	authURL, err := url.Parse(u.config.AuthURL)
	if err != nil {
		return "", err
	}

	query := authURL.Query()
	query.Set("client_id", u.config.ClientID)
	query.Set("redirect_uri", u.config.RedirectURL)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(u.config.Scopes, " "))
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

func withCode(rawURL, code string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.Wrap(err, "parse app success url")
	}

	query := parsedURL.Query()
	query.Set("code", code)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}
