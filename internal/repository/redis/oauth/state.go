package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	domain "iam/internal/domain/oauth"

	"github.com/redis/go-redis/v9"
)

const stateKeyPrefix = "oauth_state:"

type StateRepository struct {
	client redis.UniversalClient
}

func NewStateRepository(client redis.UniversalClient) *StateRepository {
	return &StateRepository{client: client}
}

func (r *StateRepository) Generate(ctx context.Context, ttl time.Duration) (string, error) {
	slog.Debug("generate oauth state",
		slog.Duration("ttl", ttl),
	)
	state, err := randomToken(32)
	if err != nil {
		slog.Error("generate random token",
			slog.Any("error", err),
		)
		return "", err
	}

	if err := r.client.Set(ctx, stateKey(state), "1", ttl).Err(); err != nil {
		slog.Error("store oauth state",
			slog.Any("error", err),
			slog.String("state", state[:8]+"..."),
		)
		return "", fmt.Errorf("store oauth state: %w", err)
	}
	slog.Debug("oauth state generated and stored",
		slog.String("state", state[:8]+"..."),
		slog.String("key", stateKey(state)),
	)

	return state, nil
}

func (r *StateRepository) Consume(ctx context.Context, state string) error {
	slog.Debug("consume oauth state",
		slog.String("state", state[:8]+"..."),
		slog.String("key", stateKey(state)),
	)
	err := r.client.GetDel(ctx, stateKey(state)).Err()
	if errors.Is(err, redis.Nil) {
		slog.Debug("oauth state not found in redis",
			slog.String("state", state[:8]+"..."),
			slog.String("key", stateKey(state)),
		)
		return domain.ErrInvalidState
	}
	if err != nil {
		slog.Error("consume oauth state",
			slog.Any("error", err),
			slog.String("state", state[:8]+"..."),
			slog.String("key", stateKey(state)),
		)
		return fmt.Errorf("consume oauth state: %w", err)
	}
	slog.Debug("oauth state consumed",
		slog.String("state", state[:8]+"..."),
		slog.String("key", stateKey(state)),
	)

	return nil
}

func stateKey(state string) string {
	return stateKeyPrefix + state
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
