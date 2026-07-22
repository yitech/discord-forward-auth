package audit

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// MemoryStore is an in-memory audit Store for tests.
type MemoryStore struct {
	mu     sync.Mutex
	nextID int64
	events []Event
	now    func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now: time.Now,
	}
}

func (s *MemoryStore) Append(_ context.Context, actor, action, target string, details map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	s.nextID++
	s.events = append(s.events, Event{
		ID:      s.nextID,
		At:      s.now().UTC(),
		Actor:   actor,
		Action:  action,
		Target:  target,
		Details: raw,
	})
	return nil
}

func (s *MemoryStore) List(_ context.Context, limit, offset int) ([]Event, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := int64(len(s.events))
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}

	// Newest first (append order is oldest→newest).
	start := int(total) - offset - 1
	if start < 0 {
		return []Event{}, total, nil
	}

	var out []Event
	for i := start; i >= 0 && len(out) < limit; i-- {
		e := s.events[i]
		cp := e
		cp.Details = append(json.RawMessage(nil), e.Details...)
		out = append(out, cp)
	}
	if out == nil {
		out = []Event{}
	}
	return out, total, nil
}
