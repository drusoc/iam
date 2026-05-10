package account

import (
	"context"
	"testing"
	"time"

	domain "iam/internal/domain/account"
	"iam/internal/usecase/account/dto"
	"iam/internal/usecase/account/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestUsecaseGetBuyIdentity(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, repository *mocks.MockRepository) dto.GetBuyIdentityIn
		check func(t *testing.T, response *dto.GetBuyIdentityOut, err error)
	}{
		{
			name: "creates_verified",
			setup: func(t *testing.T, repository *mocks.MockRepository) dto.GetBuyIdentityIn {
				identity := verifiedIdentity()
				account := createdAccount()

				repository.EXPECT().
					FindByGoogleSub(gomock.Any(), identity.Sub).
					Return(domain.Account{}, domain.ErrNotFound)

				repository.EXPECT().
					Create(gomock.Any(), identity).
					Return(account, nil)

				return request(identity)
			},
			check: func(t *testing.T, response *dto.GetBuyIdentityOut, err error) {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, int64(1), response.Account.ID)
				assert.Equal(t, domain.StatusActive, response.Account.Status)
			},
		},
		{
			name: "finds_existing",
			setup: func(t *testing.T, repository *mocks.MockRepository) dto.GetBuyIdentityIn {
				identity := verifiedIdentity()
				account := activeAccount()

				repository.EXPECT().
					FindByGoogleSub(gomock.Any(), identity.Sub).
					Return(account, nil)

				return request(identity)
			},
			check: func(t *testing.T, response *dto.GetBuyIdentityOut, err error) {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, int64(10), response.Account.ID)
			},
		},
		{
			name: "rejects_unverified_email",
			setup: func(t *testing.T, repository *mocks.MockRepository) dto.GetBuyIdentityIn {
				identity := verifiedIdentity()
				identity.EmailVerified = false

				return request(identity)
			},
			check: func(t *testing.T, _ *dto.GetBuyIdentityOut, err error) {
				require.ErrorIs(t, err, domain.ErrEmailUnverified)
			},
		},
		{
			name: "rejects_blocked",
			setup: func(t *testing.T, repository *mocks.MockRepository) dto.GetBuyIdentityIn {
				identity := verifiedIdentity()
				account := activeAccount()
				account.Status = domain.StatusBlocked

				repository.EXPECT().
					FindByGoogleSub(gomock.Any(), identity.Sub).
					Return(account, nil)

				return request(identity)
			},
			check: func(t *testing.T, _ *dto.GetBuyIdentityOut, err error) {
				require.ErrorIs(t, err, domain.ErrBlocked)
			},
		},
		{
			name: "rejects_deleted",
			setup: func(t *testing.T, repository *mocks.MockRepository) dto.GetBuyIdentityIn {
				identity := verifiedIdentity()
				account := activeAccount()
				account.Status = domain.StatusDeleted

				repository.EXPECT().
					FindByGoogleSub(gomock.Any(), identity.Sub).
					Return(account, nil)

				return request(identity)
			},
			check: func(t *testing.T, _ *dto.GetBuyIdentityOut, err error) {
				require.ErrorIs(t, err, domain.ErrDeleted)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			repository := mocks.NewMockRepository(ctrl)
			req := tt.setup(t, repository)

			uc := NewUsecase(repository)

			response, err := uc.GetBuyIdentity(context.Background(), req)

			tt.check(t, response, err)
		})
	}
}

func TestUsecaseGetByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	repository := mocks.NewMockRepository(ctrl)

	account := activeAccount()
	repository.EXPECT().
		FindByID(gomock.Any(), account.ID).
		Return(account, nil)

	uc := NewUsecase(repository)
	response, err := uc.GetByID(context.Background(), dto.GetByIDIn{ID: account.ID})

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, account.ID, response.Account.ID)
}

func request(identity domain.GoogleIdentity) dto.GetBuyIdentityIn {
	return dto.GetBuyIdentityIn{Identity: identity}
}

func verifiedIdentity() domain.GoogleIdentity {
	return domain.GoogleIdentity{
		Sub:           "google-sub",
		Email:         "user@example.com",
		EmailVerified: true,
	}
}

func activeAccount() domain.Account {
	return domain.Account{
		ID:            10,
		GoogleSub:     "google-sub",
		Email:         "user@example.com",
		EmailVerified: true,
		Status:        domain.StatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func createdAccount() domain.Account {
	return domain.Account{
		ID:            1,
		GoogleSub:     "google-sub",
		Email:         "user@example.com",
		EmailVerified: true,
		Status:        domain.StatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}
