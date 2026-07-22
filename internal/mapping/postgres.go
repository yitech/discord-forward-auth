package mapping

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) List(ctx context.Context, guildID string) ([]Mapping, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT guild_id, role_id, group_name, updated_at, updated_by
		FROM role_group_mappings
		WHERE guild_id = $1
		ORDER BY group_name, role_id
	`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Mapping
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.GuildID, &m.RoleID, &m.GroupName, &m.UpdatedAt, &m.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Upsert(ctx context.Context, guildID, roleID, groupName, updatedBy string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO role_group_mappings (guild_id, role_id, group_name, updated_at, updated_by)
		VALUES ($1, $2, $3, now(), $4)
		ON CONFLICT (guild_id, role_id, group_name)
		DO UPDATE SET updated_at = now(), updated_by = EXCLUDED.updated_by
	`, guildID, roleID, groupName, updatedBy)
	return err
}

func (s *PostgresStore) Delete(ctx context.Context, guildID, roleID, groupName string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM role_group_mappings
		WHERE guild_id = $1 AND role_id = $2 AND group_name = $3
	`, guildID, roleID, groupName)
	return err
}

func (s *PostgresStore) GroupsForRoles(ctx context.Context, guildID string, roleIDs []string) ([]string, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT group_name
		FROM role_group_mappings
		WHERE guild_id = $1 AND role_id = ANY($2)
		ORDER BY group_name
	`, guildID, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *PostgresStore) InvalidateCache() {}
