package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

var ErrNotFound = errors.New("session not found")

type Session struct {
	ID          string
	DiscordUser string
	Groups      []string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	Revoked     bool
}

type Store interface {
	Create(ctx context.Context, discordUser string, groups []string, ttl time.Duration) (*Session, error)
	GetValid(ctx context.Context, id string) (*Session, error)
	Touch(ctx context.Context, id string) error
	Revoke(ctx context.Context, id string) error
	RevokeUser(ctx context.Context, discordUser string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
