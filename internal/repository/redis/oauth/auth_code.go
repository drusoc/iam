package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	domain "iam/internal/domain/oauth"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const authCodeKeyPrefix = "oauth_auth_code:"

type AuthCodeRepository struct {
	client redis.UniversalClient
}

func NewAuthCodeRepository(client redis.UniversalClient) *AuthCodeRepository {
	return &AuthCodeRepository{client: client}
}

func (r *AuthCodeRepository) Generate(ctx context.Context, accountID int64, ttl time.Duration) (string, error) {
	slog.Debug("generate auth code",
		slog.Int64("account_id", accountID),
		slog.Duration("ttl", ttl),
	)
	code := uuid.NewString()
	if err := r.client.Set(ctx, authCodeKey(code), accountID, ttl).Err(); err != nil {
		slog.Error("store auth code",
			slog.Any("error", err),
			slog.Int64("account_id", accountID),
			slog.String("code", code[:8]+"..."),
		)
		return "", fmt.Errorf("store auth code: %w", err)
	}
	slog.Debug("auth code generated and stored",
		slog.String("code", code[:8]+"..."),
		slog.Int64("account_id", accountID),
		slog.String("key", authCodeKey(code)),
	)

	return code, nil
}

func (r *AuthCodeRepository) Consume(ctx context.Context, code string) (int64, error) {
	slog.Debug("consume auth code",
		slog.String("code", code[:8]+"..."),
		slog.String("key", authCodeKey(code)),
	)
	accountID, err := r.client.GetDel(ctx, authCodeKey(code)).Int64()
	if errors.Is(err, redis.Nil) {
		slog.Debug("auth code not found in redis",
			slog.String("code", code[:8]+"..."),
			slog.String("key", authCodeKey(code)),
		)
		return 0, domain.ErrInvalidAuthCode
	}
	if err != nil {
		slog.Error("consume auth code",
			slog.Any("error", err),
			slog.String("code", code[:8]+"..."),
			slog.String("key", authCodeKey(code)),
		)
		return 0, fmt.Errorf("consume auth code account id: %w", err)
	}
	slog.Debug("auth code consumed",
		slog.String("code", code[:8]+"..."),
		slog.Int64("account_id", accountID),
		slog.String("key", authCodeKey(code)),
	)

	return accountID, nil
}

func authCodeKey(code string) string {
	return authCodeKeyPrefix + code
}
