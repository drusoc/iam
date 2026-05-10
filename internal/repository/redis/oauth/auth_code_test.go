package oauth

import (
	"context"
	"testing"
	"time"

	domain "iam/internal/domain/oauth"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCodeRepository(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, repository *AuthCodeRepository, server *miniredis.Miniredis) string
		check func(t *testing.T, repository *AuthCodeRepository, code string)
	}{
		{
			name: "generate_and_consume_once",
			setup: func(t *testing.T, repository *AuthCodeRepository, server *miniredis.Miniredis) string {
				code, err := repository.Generate(context.Background(), 42, time.Minute)
				require.NoError(t, err)
				assert.NotEmpty(t, code)
				assert.True(t, server.Exists(authCodeKey(code)))
				return code
			},
			check: func(t *testing.T, repository *AuthCodeRepository, code string) {
				accountID, err := repository.Consume(context.Background(), code)
				require.NoError(t, err)
				assert.Equal(t, int64(42), accountID)

				_, err = repository.Consume(context.Background(), code)
				require.ErrorIs(t, err, domain.ErrInvalidAuthCode)
			},
		},
		{
			name: "unknown_code",
			setup: func(t *testing.T, repository *AuthCodeRepository, server *miniredis.Miniredis) string {
				return "missing"
			},
			check: func(t *testing.T, repository *AuthCodeRepository, code string) {
				_, err := repository.Consume(context.Background(), code)
				require.ErrorIs(t, err, domain.ErrInvalidAuthCode)
			},
		},
		{
			name: "expired_code",
			setup: func(t *testing.T, repository *AuthCodeRepository, server *miniredis.Miniredis) string {
				code, err := repository.Generate(context.Background(), 42, time.Second)
				require.NoError(t, err)
				server.FastForward(time.Second)
				return code
			},
			check: func(t *testing.T, repository *AuthCodeRepository, code string) {
				_, err := repository.Consume(context.Background(), code)
				require.ErrorIs(t, err, domain.ErrInvalidAuthCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: server.Addr()})
			t.Cleanup(func() {
				require.NoError(t, client.Close())
			})

			repository := NewAuthCodeRepository(client)
			code := tt.setup(t, repository, server)
			tt.check(t, repository, code)
		})
	}
}
