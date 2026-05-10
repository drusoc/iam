package session

import (
	"context"
	"testing"
	"time"

	"iam/internal/apperror"
	accountdomain "iam/internal/domain/account"
	sessiondomain "iam/internal/domain/session"
	accountdto "iam/internal/usecase/account/dto"
	"iam/internal/usecase/session/dto"
	"iam/internal/usecase/session/mocks"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestUsecaseGetCurrentSession(t *testing.T) {
	tests := []struct {
		name  string
		setup func(sessionRepository *mocks.MockSessionRepository, accountUsecase *mocks.MockAccountUsecase) dto.GetCurrentSessionIn
		check func(t *testing.T, response *dto.GetCurrentSessionOut, err error)
	}{
		{
			name: "valid_session",
			setup: func(sessionRepository *mocks.MockSessionRepository, accountUsecase *mocks.MockAccountUsecase) dto.GetCurrentSessionIn {
				sessionRepository.EXPECT().Get(gomock.Any(), "session-id").Return(int64(10), nil)
				accountUsecase.EXPECT().GetByID(gomock.Any(), accountdto.GetByIDIn{ID: 10}).Return(&accountdto.GetByIDOut{Account: accountdomain.Account{
					ID:     10,
					Email:  "user@example.com",
					Status: accountdomain.StatusActive,
				}}, nil)
				return dto.GetCurrentSessionIn{SessionID: "session-id"}
			},
			check: func(t *testing.T, response *dto.GetCurrentSessionOut, err error) {
				require.NoError(t, err)
				require.NotNil(t, response)
				require.Equal(t, int64(10), response.Account.ID)
			},
		},
		{
			name: "missing_session",
			setup: func(sessionRepository *mocks.MockSessionRepository, accountUsecase *mocks.MockAccountUsecase) dto.GetCurrentSessionIn {
				return dto.GetCurrentSessionIn{}
			},
			check: func(t *testing.T, response *dto.GetCurrentSessionOut, err error) {
				require.Nil(t, response)
				require.ErrorIs(t, err, sessiondomain.ErrMissingSession)
				appErr, ok := apperror.As(err)
				require.True(t, ok)
				require.Equal(t, "missing-session", appErr.Code())
			},
		},
		{
			name: "expired_session",
			setup: func(sessionRepository *mocks.MockSessionRepository, accountUsecase *mocks.MockAccountUsecase) dto.GetCurrentSessionIn {
				sessionRepository.EXPECT().Get(gomock.Any(), "expired").Return(int64(0), sessiondomain.ErrExpiredSession)
				return dto.GetCurrentSessionIn{SessionID: "expired"}
			},
			check: func(t *testing.T, response *dto.GetCurrentSessionOut, err error) {
				require.Nil(t, response)
				require.ErrorIs(t, err, sessiondomain.ErrExpiredSession)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sessionRepository := mocks.NewMockSessionRepository(ctrl)
			accountUsecase := mocks.NewMockAccountUsecase(ctrl)
			request := tt.setup(sessionRepository, accountUsecase)

			uc := NewUsecase(Config{}, sessionRepository, mocks.NewMockRefreshSessionRepository(ctrl), accountUsecase)
			response, err := uc.GetCurrentSession(context.Background(), request)

			tt.check(t, response, err)
		})
	}
}

func TestUsecaseLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessionRepository := mocks.NewMockSessionRepository(ctrl)
	refreshRepository := mocks.NewMockRefreshSessionRepository(ctrl)

	sessionRepository.EXPECT().Delete(gomock.Any(), "session-id").Return(nil)

	uc := NewUsecase(Config{}, sessionRepository, refreshRepository, mocks.NewMockAccountUsecase(ctrl))

	response, err := uc.Logout(context.Background(), dto.LogoutIn{SessionID: "session-id"})
	require.NoError(t, err)
	require.NotNil(t, response)
}

func TestUsecaseRefresh(t *testing.T) {
	now := time.Now()
	account := accountdomain.Account{ID: 10, Status: accountdomain.StatusActive}

	t.Run("success_rotates_token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		sessionRepo := mocks.NewMockSessionRepository(ctrl)
		refreshRepo := mocks.NewMockRefreshSessionRepository(ctrl)
		accountUC := mocks.NewMockAccountUsecase(ctrl)

		refreshSession := &sessiondomain.RefreshSession{
			ID:                "refresh-1",
			AccountID:         10,
			FamilyID:          "family-1",
			CreatedAt:         now.Add(-1 * time.Hour),
			ExpiresAt:         now.Add(1 * time.Hour),
			AbsoluteExpiresAt: now.Add(30 * 24 * time.Hour),
		}

		refreshRepo.EXPECT().LoadByTokenHash(gomock.Any(), gomock.Any()).Return(refreshSession, nil)
		accountUC.EXPECT().GetByID(gomock.Any(), accountdto.GetByIDIn{ID: 10}).Return(&accountdto.GetByIDOut{Account: account}, nil)
		refreshRepo.EXPECT().MarkUsed(gomock.Any(), "refresh-1").Return(nil)
		sessionRepo.EXPECT().Create(gomock.Any(), int64(10), gomock.Any()).Return("new-session", nil)
		refreshRepo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, s sessiondomain.RefreshSession) (string, error) {
				require.Equal(t, "family-1", s.FamilyID)
				require.Equal(t, "refresh-1", s.ParentID)
				require.Equal(t, int64(10), s.AccountID)
				return "new-refresh-token", nil
			},
		)

		uc := NewUsecase(Config{
			SessionTTL:         24 * time.Hour,
			RefreshTTL:         24 * time.Hour,
			RefreshAbsoluteTTL: 720 * time.Hour,
		}, sessionRepo, refreshRepo, accountUC)

		response, err := uc.Refresh(context.Background(), dto.RefreshIn{RefreshToken: "valid-token"})

		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, "new-session", response.SessionID)
		require.Equal(t, "new-refresh-token", response.RefreshToken)
	})

	t.Run("missing_token_returns_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		uc := NewUsecase(Config{}, mocks.NewMockSessionRepository(ctrl), mocks.NewMockRefreshSessionRepository(ctrl), mocks.NewMockAccountUsecase(ctrl))

		response, err := uc.Refresh(context.Background(), dto.RefreshIn{})

		require.Nil(t, response)
		require.ErrorIs(t, err, sessiondomain.ErrMissingRefresh)
	})

	t.Run("used_token_revokes_family", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		sessionRepo := mocks.NewMockSessionRepository(ctrl)
		refreshRepo := mocks.NewMockRefreshSessionRepository(ctrl)
		accountUC := mocks.NewMockAccountUsecase(ctrl)

		usedAt := now.Add(-30 * time.Minute)
		refreshSession := &sessiondomain.RefreshSession{
			ID:        "refresh-1",
			AccountID: 10,
			FamilyID:  "family-1",
			UsedAt:    &usedAt,
		}

		refreshRepo.EXPECT().LoadByTokenHash(gomock.Any(), gomock.Any()).Return(refreshSession, nil)
		refreshRepo.EXPECT().RevokeFamily(gomock.Any(), "family-1").Return(nil)

		uc := NewUsecase(Config{}, sessionRepo, refreshRepo, accountUC)

		response, err := uc.Refresh(context.Background(), dto.RefreshIn{RefreshToken: "used-token"})

		require.Nil(t, response)
		require.ErrorIs(t, err, sessiondomain.ErrUsedRefresh)
	})
}
