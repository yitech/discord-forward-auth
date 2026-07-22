package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Create(ctx context.Context, discordUser string, groups []string, ttl time.Duration) (*Session, error) {
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	if groups == nil {
		groups = []string{}
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO auth_sessions (id, discord_user, groups, created_at, last_seen_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $4, $5, false)
	`, id, discordUser, groups, now, expires)
	if err != nil {
		return nil, err
	}
	return &Session{
		ID:          id,
		DiscordUser: discordUser,
		Groups:      groups,
		CreatedAt:   now,
		LastSeenAt:  now,
		ExpiresAt:   expires,
		Revoked:     false,
	}, nil
}

func (s *PostgresStore) GetValid(ctx context.Context, id string) (*Session, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, discord_user, groups, created_at, last_seen_at, expires_at, revoked
		FROM auth_sessions
		WHERE id = $1 AND NOT revoked AND expires_at > now()
	`, id)

	var sess Session
	err := row.Scan(
		&sess.ID,
		&sess.DiscordUser,
		&sess.Groups,
		&sess.CreatedAt,
		&sess.LastSeenAt,
		&sess.ExpiresAt,
		&sess.Revoked,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *PostgresStore) Touch(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE auth_sessions SET last_seen_at = now() WHERE id = $1
	`, id)
	return err
}

func (s *PostgresStore) Revoke(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE auth_sessions SET revoked = true WHERE id = $1
	`, id)
	return err
}

func (s *PostgresStore) RevokeUser(ctx context.Context, discordUser string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE auth_sessions SET revoked = true WHERE discord_user = $1 AND NOT revoked
	`, discordUser)
	return err
}

func (s *PostgresStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM auth_sessions WHERE expires_at < now() OR revoked = true
	`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
