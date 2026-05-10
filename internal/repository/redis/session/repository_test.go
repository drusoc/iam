package session

import (
	"context"
	"testing"
	"time"

	sessiondomain "iam/internal/domain/session"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepositoryCreateGetDelete(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	repository := NewRepository(client)

	sessionID, err := repository.Create(context.Background(), 42, time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	accountID, err := repository.Get(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, int64(42), accountID)

	require.NoError(t, repository.Delete(context.Background(), sessionID))
	_, err = repository.Get(context.Background(), sessionID)
	require.ErrorIs(t, err, sessiondomain.ErrExpiredSession)
}

func TestRepositoryGetExpired(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	repository := NewRepository(client)
	sessionID, err := repository.Create(context.Background(), 42, time.Second)
	require.NoError(t, err)

	server.FastForward(time.Second)
	_, err = repository.Get(context.Background(), sessionID)
	require.ErrorIs(t, err, sessiondomain.ErrExpiredSession)
}
