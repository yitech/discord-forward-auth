package mapping

import (
	"context"
	"sync"
	"time"
)

type MemoryStore struct {
	mu   sync.Mutex
	rows []Mapping
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) List(_ context.Context, guildID string) ([]Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Mapping
	for _, m := range s.rows {
		if m.GuildID == guildID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *MemoryStore) Upsert(_ context.Context, guildID, roleID, groupName, updatedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	by := updatedBy
	for i, m := range s.rows {
		if m.GuildID == guildID && m.RoleID == roleID && m.GroupName == groupName {
			s.rows[i].UpdatedAt = now
			s.rows[i].UpdatedBy = &by
			return nil
		}
	}
	s.rows = append(s.rows, Mapping{
		GuildID:   guildID,
		RoleID:    roleID,
		GroupName: groupName,
		UpdatedAt: now,
		UpdatedBy: &by,
	})
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, guildID, roleID, groupName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.rows[:0]
	for _, m := range s.rows {
		if m.GuildID == guildID && m.RoleID == roleID && m.GroupName == groupName {
			continue
		}
		out = append(out, m)
	}
	s.rows = out
	return nil
}

func (s *MemoryStore) GroupsForRoles(ctx context.Context, guildID string, roleIDs []string) ([]string, error) {
	list, err := s.List(ctx, guildID)
	if err != nil {
		return nil, err
	}
	want := map[string]struct{}{}
	for _, id := range roleIDs {
		want[id] = struct{}{}
	}
	seen := map[string]struct{}{}
	var groups []string
	for _, m := range list {
		if _, ok := want[m.RoleID]; !ok {
			continue
		}
		if _, ok := seen[m.GroupName]; ok {
			continue
		}
		seen[m.GroupName] = struct{}{}
		groups = append(groups, m.GroupName)
	}
	return groups, nil
}

func (s *MemoryStore) InvalidateCache() {}
