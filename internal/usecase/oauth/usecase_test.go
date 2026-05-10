package oauth

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"iam/internal/apperror"
	accountdomain "iam/internal/domain/account"
	oauthdomain "iam/internal/domain/oauth"
	accountdto "iam/internal/usecase/account/dto"
	"iam/internal/usecase/oauth/dto"
	"iam/internal/usecase/oauth/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestUsecaseStartGoogleAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	stateRepository := mocks.NewMockStateRepository(ctrl)
	uc := NewUsecase(
		testConfig(),
		stateRepository,
		mocks.NewMockAuthCodeRepository(ctrl),
		mocks.NewMockSessionRepository(ctrl),
		mocks.NewMockRefreshSessionRepository(ctrl),
		mocks.NewMockGoogleProvider(ctrl),
		mocks.NewMockAccountUsecase(ctrl),
	)

	stateRepository.EXPECT().Generate(gomock.Any(), 10*time.Minute).Return("state-123", nil)

	response, err := uc.StartGoogleAuth(context.Background(), dto.StartGoogleAuthIn{})

	require.NoError(t, err)
	require.NotNil(t, response)

	redirectURL, err := url.Parse(response.RedirectURL)
	require.NoError(t, err)
	assert.Equal(t, "state-123", response.State)
	assert.Equal(t, "state-123", redirectURL.Query().Get("state"))
}

func TestUsecaseHandleGoogleCallback(t *testing.T) {
	identity := accountdomain.GoogleIdentity{
		Sub:           "google-sub",
		Email:         "user@example.com",
		EmailVerified: true,
	}
	account := accountdomain.Account{ID: 10, Status: accountdomain.StatusActive}

	tests := []struct {
		name  string
		setup func(
			state *mocks.MockStateRepository,
			authCode *mocks.MockAuthCodeRepository,
			google *mocks.MockGoogleProvider,
			accountUC *mocks.MockAccountUsecase,
		)
		request dto.HandleGoogleCallbackIn
		check   func(t *testing.T, response *dto.HandleGoogleCallbackOut, err error)
	}{
		{
			name: "success",
			setup: func(
				state *mocks.MockStateRepository,
				authCode *mocks.MockAuthCodeRepository,
				google *mocks.MockGoogleProvider,
				accountUC *mocks.MockAccountUsecase,
			) {
				state.EXPECT().Consume(gomock.Any(), "state-123").Return(nil)
				google.EXPECT().ExchangeCode(gomock.Any(), "code-123").Return(identity, nil)
				accountUC.EXPECT().
					GetBuyIdentity(gomock.Any(), accountdto.GetBuyIdentityIn{Identity: identity}).
					Return(&accountdto.GetBuyIdentityOut{Account: account}, nil)
				authCode.EXPECT().Generate(gomock.Any(), int64(10), 2*time.Minute).Return("one-time", nil)
			},
			request: dto.HandleGoogleCallbackIn{Code: "code-123", State: "state-123"},
			check: func(t *testing.T, response *dto.HandleGoogleCallbackOut, err error) {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, "one-time", mustQuery(t, response.RedirectURL, "code"))
			},
		},
		{
			name: "missing_state",
			setup: func(*mocks.MockStateRepository, *mocks.MockAuthCodeRepository, *mocks.MockGoogleProvider, *mocks.MockAccountUsecase) {
			},
			request: dto.HandleGoogleCallbackIn{
				Code: "code-123",
			},
			check: func(t *testing.T, response *dto.HandleGoogleCallbackOut, err error) {
				require.Nil(t, response)
				appErr, ok := apperror.As(err)
				require.True(t, ok)
				assert.Equal(t, "missing-state", appErr.Code())
			},
		},
		{
			name: "invalid_token",
			setup: func(
				state *mocks.MockStateRepository,
				authCode *mocks.MockAuthCodeRepository,
				google *mocks.MockGoogleProvider,
				accountUC *mocks.MockAccountUsecase,
			) {
				state.EXPECT().Consume(gomock.Any(), "state-123").Return(nil)
				google.EXPECT().ExchangeCode(gomock.Any(), "code-123").Return(accountdomain.GoogleIdentity{}, oauthdomain.ErrInvalidToken)
			},
			request: dto.HandleGoogleCallbackIn{Code: "code-123", State: "state-123"},
			check: func(t *testing.T, response *dto.HandleGoogleCallbackOut, err error) {
				require.Nil(t, response)
				appErr, ok := apperror.As(err)
				require.True(t, ok)
				assert.Equal(t, "invalid-token", appErr.Code())
				assert.True(t, errors.Is(err, oauthdomain.ErrInvalidToken))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			state := mocks.NewMockStateRepository(ctrl)
			authCode := mocks.NewMockAuthCodeRepository(ctrl)
			google := mocks.NewMockGoogleProvider(ctrl)
			accountUC := mocks.NewMockAccountUsecase(ctrl)
			refreshSession := mocks.NewMockRefreshSessionRepository(ctrl)
			tt.setup(state, authCode, google, accountUC)

			uc := NewUsecase(
				testConfig(),
				state,
				authCode,
				mocks.NewMockSessionRepository(ctrl),
				refreshSession,
				google,
				accountUC,
			)

			response, err := uc.HandleGoogleCallback(context.Background(), tt.request)
			tt.check(t, response, err)
		})
	}
}

func TestUsecaseExchangeAuthCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	authCode := mocks.NewMockAuthCodeRepository(ctrl)
	session := mocks.NewMockSessionRepository(ctrl)
	refreshSession := mocks.NewMockRefreshSessionRepository(ctrl)

	authCode.EXPECT().Consume(gomock.Any(), "auth-code").Return(int64(77), nil)
	session.EXPECT().Create(gomock.Any(), int64(77), 24*time.Hour).Return("session-id", nil)
	refreshSession.EXPECT().Create(gomock.Any(), gomock.Any()).Return("refresh-token", nil)

	uc := NewUsecase(
		testConfig(),
		mocks.NewMockStateRepository(ctrl),
		authCode,
		session,
		refreshSession,
		mocks.NewMockGoogleProvider(ctrl),
		mocks.NewMockAccountUsecase(ctrl),
	)

	response, err := uc.ExchangeAuthCode(context.Background(), dto.ExchangeAuthCodeIn{Code: "auth-code"})

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "session-id", response.SessionID)
	assert.Equal(t, "refresh-token", response.RefreshToken)
}

func testConfig() Config {
	return Config{
		ClientID:      "client-id",
		AuthURL:       "https://accounts.google.com/o/oauth2/auth",
		RedirectURL:   "http://localhost:8080/api/1/auth/google/callback",
		AppSuccessURL: "http://localhost:3000/auth/success",
		Scopes:        []string{"openid", "email", "profile"},
		StateTTL:      10 * time.Minute,
		AuthCodeTTL:   2 * time.Minute,
		SessionTTL:    24 * time.Hour,
	}
}

func mustQuery(t *testing.T, rawURL string, key string) string {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	return parsed.Query().Get(key)
}
