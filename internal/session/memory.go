package session

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory SessionStore for tests.
type MemoryStore struct {
	mu   sync.Mutex
	byID map[string]*Session
	now  func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID: make(map[string]*Session),
		now:  time.Now,
	}
}

func (s *MemoryStore) Create(_ context.Context, discordUser string, groups []string, ttl time.Duration) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if groups == nil {
		groups = []string{}
	}
	sess := &Session{
		ID:          id,
		DiscordUser: discordUser,
		Groups:      append([]string(nil), groups...),
		CreatedAt:   now,
		LastSeenAt:  now,
		ExpiresAt:   now.Add(ttl),
	}
	s.byID[id] = sess
	return clone(sess), nil
}

func (s *MemoryStore) GetValid(_ context.Context, id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok || sess.Revoked || !sess.ExpiresAt.After(s.now().UTC()) {
		return nil, ErrNotFound
	}
	return clone(sess), nil
}

func (s *MemoryStore) Touch(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byID[id]; ok {
		sess.LastSeenAt = s.now().UTC()
	}
	return nil
}

func (s *MemoryStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byID[id]; ok {
		sess.Revoked = true
	}
	return nil
}

func (s *MemoryStore) RevokeUser(_ context.Context, discordUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.byID {
		if sess.DiscordUser == discordUser {
			sess.Revoked = true
		}
	}
	return nil
}

func (s *MemoryStore) DeleteExpired(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	now := s.now().UTC()
	for id, sess := range s.byID {
		if sess.Revoked || !sess.ExpiresAt.After(now) {
			delete(s.byID, id)
			n++
		}
	}
	return n, nil
}

func clone(s *Session) *Session {
	cp := *s
	cp.Groups = append([]string(nil), s.Groups...)
	return &cp
}
