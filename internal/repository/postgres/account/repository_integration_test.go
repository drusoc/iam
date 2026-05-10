package account

import (
	"context"
	"database/sql"
	"os"
	"testing"

	domain "iam/internal/domain/account"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepositoryIntegration(t *testing.T) {
	dsn := os.Getenv("IAM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("IAM_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	sqlDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, sqlDB.Close())
	})

	require.NoError(t, resetPublicSchema(sqlDB))
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(sqlDB, "../../../../migrations"))

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := NewRepository(pool)

	t.Run("create_and_find", func(t *testing.T) {
		account, err := repo.Create(ctx, domain.GoogleIdentity{
			Sub:           "google-sub-1",
			Email:         "same@example.com",
			EmailVerified: true,
		})
		require.NoError(t, err)
		assert.NotZero(t, account.ID)
		assert.Equal(t, domain.StatusActive, account.Status)

		found, err := repo.FindByGoogleSub(ctx, "google-sub-1")
		require.NoError(t, err)
		assert.Equal(t, account.ID, found.ID)
	})

	t.Run("duplicate_google_sub", func(t *testing.T) {
		_, err := repo.Create(ctx, domain.GoogleIdentity{
			Sub:           "google-sub-2",
			Email:         "first@example.com",
			EmailVerified: true,
		})
		require.NoError(t, err)

		_, err = repo.Create(ctx, domain.GoogleIdentity{
			Sub:           "google-sub-2",
			Email:         "second@example.com",
			EmailVerified: true,
		})
		require.Error(t, err)
	})

	t.Run("email_not_unique", func(t *testing.T) {
		_, err := repo.Create(ctx, domain.GoogleIdentity{
			Sub:           "google-sub-3",
			Email:         "shared@example.com",
			EmailVerified: true,
		})
		require.NoError(t, err)

		_, err = repo.Create(ctx, domain.GoogleIdentity{
			Sub:           "google-sub-4",
			Email:         "shared@example.com",
			EmailVerified: true,
		})
		require.NoError(t, err)
	})

	t.Run("soft_delete_status", func(t *testing.T) {
		account, err := repo.Create(ctx, domain.GoogleIdentity{
			Sub:           "google-sub-5",
			Email:         "delete@example.com",
			EmailVerified: true,
		})
		require.NoError(t, err)

		deleted, err := repo.SetStatus(ctx, account.ID, domain.StatusDeleted)
		require.NoError(t, err)
		assert.Equal(t, domain.StatusDeleted, deleted.Status)

		found, err := repo.FindByGoogleSub(ctx, "google-sub-5")
		require.NoError(t, err)
		assert.Equal(t, domain.StatusDeleted, found.Status)
	})
}

func resetPublicSchema(db *sql.DB) error {
	if _, err := db.Exec(`DROP SCHEMA public CASCADE`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE SCHEMA public`); err != nil {
		return err
	}
	_, err := db.Exec(`GRANT ALL ON SCHEMA public TO public`)
	return err
}
