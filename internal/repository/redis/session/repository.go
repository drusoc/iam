package session

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	oauthdomain "iam/internal/domain/oauth"
	sessiondomain "iam/internal/domain/session"

	fasterrors "github.com/go-faster/errors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const sessionKeyPrefix = "iam_session:"

type Repository struct {
	client redis.UniversalClient
}

func NewRepository(client redis.UniversalClient) *Repository {
	return &Repository{client: client}
}

func (r *Repository) Create(ctx context.Context, accountID int64, ttl time.Duration) (string, error) {
	slog.Debug("create session",
		slog.Int64("account_id", accountID),
		slog.Duration("ttl", ttl),
	)
	sessionID := uuid.NewString()

	if err := r.client.Set(ctx, sessionKey(sessionID), strconv.FormatInt(accountID, 10), ttl).Err(); err != nil {
		slog.Error("store session",
			slog.Any("error", err),
			slog.Int64("account_id", accountID),
			slog.String("session_id", sessionID[:8]+"..."),
		)
		return "", fasterrors.Wrapf(oauthdomain.ErrSessionCreate, "store session: %v", err)
	}
	slog.Debug("session created and stored",
		slog.String("session_id", sessionID[:8]+"..."),
		slog.Int64("account_id", accountID),
		slog.String("key", sessionKey(sessionID)),
	)

	return sessionID, nil
}

func (r *Repository) Get(ctx context.Context, sessionID string) (int64, error) {
	slog.Debug("get session",
		slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
		slog.String("key", sessionKey(sessionID)),
	)
	if sessionID == "" {
		slog.Warn("empty session id")
		return 0, sessiondomain.ErrInvalidSession
	}

	storedAccountID, err := r.client.Get(ctx, sessionKey(sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		slog.Debug("session not found in redis",
			slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
			slog.String("key", sessionKey(sessionID)),
		)
		return 0, sessiondomain.ErrExpiredSession
	}
	if err != nil {
		slog.Error("get session",
			slog.Any("error", err),
			slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
			slog.String("key", sessionKey(sessionID)),
		)
		return 0, fasterrors.Wrap(err, "get session")
	}

	accountID, err := strconv.ParseInt(storedAccountID, 10, 64)
	if err != nil {
		slog.Error("parse account id from session",
			slog.Any("error", err),
			slog.String("stored_value", storedAccountID),
			slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
		)
		return 0, fasterrors.Wrap(sessiondomain.ErrInvalidSession, "parse account id from session")
	}
	slog.Debug("session found",
		slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
		slog.Int64("account_id", accountID),
	)

	return accountID, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *Repository) Delete(ctx context.Context, sessionID string) error {
	slog.Debug("delete session",
		slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
		slog.String("key", sessionKey(sessionID)),
	)
	if sessionID == "" {
		slog.Warn("empty session id in delete")
		return sessiondomain.ErrInvalidSession
	}

	deleted, err := r.client.Del(ctx, sessionKey(sessionID)).Result()
	if err != nil {
		slog.Error("delete session",
			slog.Any("error", err),
			slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
			slog.String("key", sessionKey(sessionID)),
		)
		return fasterrors.Wrap(err, "delete session")
	}
	if deleted == 0 {
		slog.Debug("session not found for deletion",
			slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
			slog.String("key", sessionKey(sessionID)),
		)
		return sessiondomain.ErrExpiredSession
	}
	slog.Debug("session deleted",
		slog.String("session_id", sessionID[:min(8, len(sessionID))]+"..."),
		slog.String("key", sessionKey(sessionID)),
	)

	return nil
}

func sessionKey(sessionID string) string {
	return sessionKeyPrefix + sessionID
}
