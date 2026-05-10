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

func TestStateRepository(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, repository *StateRepository, server *miniredis.Miniredis) string
		check func(t *testing.T, repository *StateRepository, state string, err error)
	}{
		{
			name: "generate",
			setup: func(t *testing.T, repository *StateRepository, server *miniredis.Miniredis) string {
				state, err := repository.Generate(context.Background(), time.Minute)
				require.NoError(t, err)
				assert.NotEmpty(t, state)
				assert.True(t, server.Exists(stateKey(state)))
				return state
			},
			check: func(t *testing.T, _ *StateRepository, _ string, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "consume",
			setup: func(t *testing.T, repository *StateRepository, _ *miniredis.Miniredis) string {
				state, err := repository.Generate(context.Background(), time.Minute)
				require.NoError(t, err)
				return state
			},
			check: func(t *testing.T, repository *StateRepository, state string, _ error) {
				require.NoError(t, repository.Consume(context.Background(), state))
				require.ErrorIs(t, repository.Consume(context.Background(), state), domain.ErrInvalidState)
			},
		},
		{
			name: "unknown",
			setup: func(t *testing.T, _ *StateRepository, _ *miniredis.Miniredis) string {
				return "unknown"
			},
			check: func(t *testing.T, repository *StateRepository, state string, _ error) {
				require.ErrorIs(t, repository.Consume(context.Background(), state), domain.ErrInvalidState)
			},
		},
		{
			name: "expired",
			setup: func(t *testing.T, repository *StateRepository, server *miniredis.Miniredis) string {
				state, err := repository.Generate(context.Background(), time.Second)
				require.NoError(t, err)
				server.FastForward(time.Second)
				return state
			},
			check: func(t *testing.T, repository *StateRepository, state string, _ error) {
				require.ErrorIs(t, repository.Consume(context.Background(), state), domain.ErrInvalidState)
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
			repository := NewStateRepository(client)

			state := tt.setup(t, repository, server)

			tt.check(t, repository, state, nil)
		})
	}
}
