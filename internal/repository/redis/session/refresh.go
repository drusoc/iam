package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"time"

	sessiondomain "iam/internal/domain/session"

	"github.com/go-faster/errors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const refreshKeyPrefix = "iam_refresh:"
const refreshHashKeyPrefix = "iam_refresh_hash:"
const refreshFamilyKeyPrefix = "iam_refresh_family:"
const refreshTokenLen = 32

type RefreshRepository struct {
	client redis.UniversalClient
}

func NewRefreshRepository(client redis.UniversalClient) *RefreshRepository {
	return &RefreshRepository{client: client}
}

func (r *RefreshRepository) Create(ctx context.Context, session sessiondomain.RefreshSession) (string, error) {
	slog.Debug("create refresh session",
		slog.Int64("account_id", session.AccountID),
		slog.String("family_id", session.FamilyID[:min(8, len(session.FamilyID))]+"..."),
	)
	token := uuid.NewString()

	createdSession := session
	createdSession.ID = uuid.NewString()
	createdSession.TokenHash = sessiondomain.HashToken(token)

	createdAt := time.Now()
	createdSession.CreatedAt = createdAt
	createdSession.ExpiresAt = createdAt.Add(time.Until(session.ExpiresAt))
	createdSession.AbsoluteExpiresAt = session.AbsoluteExpiresAt

	data, err := json.Marshal(createdSession)
	if err != nil {
		slog.Error("marshal refresh session",
			slog.Any("error", err),
			slog.Int64("account_id", session.AccountID),
		)
		return "", errors.Wrap(err, "marshal refresh session")
	}

	ttl := time.Until(session.AbsoluteExpiresAt)
	if err = r.client.Set(ctx, refreshKey(createdSession.ID), data, ttl).Err(); err != nil {
		slog.Error("store refresh session",
			slog.Any("error", err),
			slog.String("session_id", createdSession.ID[:8]+"..."),
			slog.Int64("account_id", session.AccountID),
		)
		return "", errors.Wrap(err, "store refresh session")
	}

	if err = r.client.Set(ctx, refreshHashKey(createdSession.TokenHash), createdSession.ID, ttl).Err(); err != nil {
		slog.Error("store refresh hash",
			slog.Any("error", err),
			slog.String("session_id", createdSession.ID[:8]+"..."),
			slog.Int64("account_id", session.AccountID),
		)
		return "", errors.Wrap(err, "store refresh hash")
	}

	if err = r.client.SAdd(ctx, refreshFamilyKey(createdSession.FamilyID), createdSession.ID).Err(); err != nil {
		slog.Error("add to refresh family",
			slog.Any("error", err),
			slog.String("family_id", createdSession.FamilyID[:min(8, len(createdSession.FamilyID))]+"..."),
			slog.String("session_id", createdSession.ID[:8]+"..."),
		)
		return "", errors.Wrap(err, "add to refresh family")
	}
	r.client.Expire(ctx, refreshFamilyKey(createdSession.FamilyID), ttl)

	slog.Debug("refresh session created",
		slog.String("session_id", createdSession.ID[:8]+"..."),
		slog.String("family_id", createdSession.FamilyID[:min(8, len(createdSession.FamilyID))]+"..."),
		slog.Int64("account_id", session.AccountID),
		slog.Duration("ttl", ttl),
	)
	return token, nil
}

func (r *RefreshRepository) LoadByTokenHash(ctx context.Context, tokenHash string) (*sessiondomain.RefreshSession, error) {
	sessionID, err := r.client.Get(ctx, refreshHashKey(tokenHash)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, sessiondomain.ErrInvalidRefresh
	}
	if err != nil {
		return nil, errors.Wrap(err, "lookup refresh by hash")
	}

	data, err := r.client.Get(ctx, refreshKey(sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, sessiondomain.ErrExpiredRefresh
	}
	if err != nil {
		return nil, errors.Wrap(err, "load refresh session")
	}

	var session sessiondomain.RefreshSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, errors.Wrap(err, "unmarshal refresh session")
	}

	return &session, nil
}

func (r *RefreshRepository) MarkUsed(ctx context.Context, sessionID string) error {
	data, err := r.client.Get(ctx, refreshKey(sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return sessiondomain.ErrExpiredRefresh
	}
	if err != nil {
		return errors.Wrap(err, "load refresh for mark used")
	}

	var session sessiondomain.RefreshSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return errors.Wrap(err, "unmarshal refresh session")
	}

	now := time.Now()
	session.UsedAt = &now

	updated, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(err, "marshal updated refresh session")
	}

	ttl := time.Until(session.AbsoluteExpiresAt)
	if err := r.client.Set(ctx, refreshKey(sessionID), updated, ttl).Err(); err != nil {
		return errors.Wrap(err, "update refresh used")
	}

	return nil
}

func (r *RefreshRepository) Revoke(ctx context.Context, sessionID string) error {
	data, err := r.client.Get(ctx, refreshKey(sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "load refresh for revoke")
	}

	var session sessiondomain.RefreshSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return errors.Wrap(err, "unmarshal refresh session")
	}

	now := time.Now()
	session.RevokedAt = &now

	updated, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(err, "marshal revoked refresh session")
	}

	ttl := time.Until(session.AbsoluteExpiresAt)
	if err := r.client.Set(ctx, refreshKey(sessionID), updated, ttl).Err(); err != nil {
		return errors.Wrap(err, "update refresh revoked")
	}

	return nil
}

func (r *RefreshRepository) RevokeFamily(ctx context.Context, familyID string) error {
	sessionIDs, err := r.client.SMembers(ctx, refreshFamilyKey(familyID)).Result()
	if err != nil {
		return errors.Wrap(err, "get family members")
	}

	for _, sessionID := range sessionIDs {
		if revokeErr := r.Revoke(ctx, sessionID); revokeErr != nil {
			return errors.Wrap(revokeErr, "revoke family member")
		}
	}

	return nil
}

func generateRefreshToken() (string, error) {
	buf := make([]byte, refreshTokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Wrap(err, "generate random token")
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func refreshKey(sessionID string) string {
	return refreshKeyPrefix + sessionID
}

func refreshHashKey(tokenHash string) string {
	return refreshHashKeyPrefix + tokenHash
}

func refreshFamilyKey(familyID string) string {
	return refreshFamilyKeyPrefix + familyID
}
