package hostpolicy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yitech/discord-forward-auth/internal/config"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) List(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host, required_groups, updated_at, updated_by
		FROM host_group_policies
		ORDER BY host
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.Host, &p.RequiredGroups, &p.UpdatedAt, &p.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Get(ctx context.Context, host string) (*Policy, error) {
	host = config.NormalizeHost(host)
	var p Policy
	err := s.pool.QueryRow(ctx, `
		SELECT host, required_groups, updated_at, updated_by
		FROM host_group_policies
		WHERE host = $1
	`, host).Scan(&p.Host, &p.RequiredGroups, &p.UpdatedAt, &p.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *PostgresStore) Upsert(ctx context.Context, host string, requiredGroups []string, updatedBy string) error {
	host = config.NormalizeHost(host)
	groups := NormalizeGroups(requiredGroups)
	if host == "" || len(groups) == 0 {
		return ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_group_policies (host, required_groups, updated_at, updated_by)
		VALUES ($1, $2, now(), $3)
		ON CONFLICT (host)
		DO UPDATE SET required_groups = EXCLUDED.required_groups,
		              updated_at = now(),
		              updated_by = EXCLUDED.updated_by
	`, host, groups, updatedBy)
	return err
}

func (s *PostgresStore) Delete(ctx context.Context, host string) error {
	host = config.NormalizeHost(host)
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM host_group_policies
		WHERE host = $1
	`, host)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
