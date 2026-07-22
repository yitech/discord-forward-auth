package hostpolicy

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yitech/discord-forward-auth/internal/config"
)

type MemoryStore struct {
	mu   sync.Mutex
	rows map[string]Policy
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: make(map[string]Policy)}
}

func (s *MemoryStore) List(_ context.Context) ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, 0, len(s.rows))
	for _, p := range s.rows {
		out = append(out, clonePolicy(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

func (s *MemoryStore) Get(_ context.Context, host string) (*Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host = config.NormalizeHost(host)
	p, ok := s.rows[host]
	if !ok {
		return nil, ErrNotFound
	}
	cp := clonePolicy(p)
	return &cp, nil
}

func (s *MemoryStore) Upsert(_ context.Context, host string, requiredGroups []string, updatedBy string) error {
	host = config.NormalizeHost(host)
	groups := NormalizeGroups(requiredGroups)
	if host == "" || len(groups) == 0 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	by := updatedBy
	s.rows[host] = Policy{
		Host:           host,
		RequiredGroups: groups,
		UpdatedAt:      now,
		UpdatedBy:      &by,
	}
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	host = config.NormalizeHost(host)
	if _, ok := s.rows[host]; !ok {
		return ErrNotFound
	}
	delete(s.rows, host)
	return nil
}

func clonePolicy(p Policy) Policy {
	groups := append([]string(nil), p.RequiredGroups...)
	var by *string
	if p.UpdatedBy != nil {
		v := *p.UpdatedBy
		by = &v
	}
	return Policy{
		Host:           p.Host,
		RequiredGroups: groups,
		UpdatedAt:      p.UpdatedAt,
		UpdatedBy:      by,
	}
}
