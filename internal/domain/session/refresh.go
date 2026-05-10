package session

import (
	"crypto/sha256"
	"encoding/base64"
	"time"
)

type RefreshSession struct {
	ID                string
	AccountID         int64
	TokenHash         string
	FamilyID          string
	ParentID          string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	UsedAt            *time.Time
	RevokedAt         *time.Time
	IP                string
	UserAgent         string
}

func (s RefreshSession) IsUsed() bool {
	return s.UsedAt != nil
}

func (s RefreshSession) IsRevoked() bool {
	return s.RevokedAt != nil
}

func (s RefreshSession) IsExpired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

func (s RefreshSession) IsAbsoluteExpired(now time.Time) bool {
	return now.After(s.AbsoluteExpiresAt)
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}
