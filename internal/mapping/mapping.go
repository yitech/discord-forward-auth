package mapping

import (
	"context"
	"sync"
	"time"
)

type Mapping struct {
	GuildID   string    `json:"guild_id"`
	RoleID    string    `json:"role_id"`
	GroupName string    `json:"group_name"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy *string   `json:"updated_by,omitempty"`
}

type Store interface {
	List(ctx context.Context, guildID string) ([]Mapping, error)
	Upsert(ctx context.Context, guildID, roleID, groupName, updatedBy string) error
	Delete(ctx context.Context, guildID, roleID, groupName string) error
	GroupsForRoles(ctx context.Context, guildID string, roleIDs []string) ([]string, error)
	InvalidateCache()
}

type CachedStore struct {
	inner Store
	ttl   time.Duration

	mu        sync.RWMutex
	cache     map[string][]string // roleID -> groups
	guildID   string
	expiresAt time.Time
}

func NewCachedStore(inner Store, ttl time.Duration) *CachedStore {
	return &CachedStore{
		inner: inner,
		ttl:   ttl,
		cache: make(map[string][]string),
	}
}

func (c *CachedStore) List(ctx context.Context, guildID string) ([]Mapping, error) {
	return c.inner.List(ctx, guildID)
}

func (c *CachedStore) Upsert(ctx context.Context, guildID, roleID, groupName, updatedBy string) error {
	if err := c.inner.Upsert(ctx, guildID, roleID, groupName, updatedBy); err != nil {
		return err
	}
	c.InvalidateCache()
	return nil
}

func (c *CachedStore) Delete(ctx context.Context, guildID, roleID, groupName string) error {
	if err := c.inner.Delete(ctx, guildID, roleID, groupName); err != nil {
		return err
	}
	c.InvalidateCache()
	return nil
}

func (c *CachedStore) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string][]string)
	c.guildID = ""
	c.expiresAt = time.Time{}
}

func (c *CachedStore) GroupsForRoles(ctx context.Context, guildID string, roleIDs []string) ([]string, error) {
	if c.ttl == 0 {
		return c.inner.GroupsForRoles(ctx, guildID, roleIDs)
	}

	c.mu.RLock()
	fresh := c.guildID == guildID && time.Now().Before(c.expiresAt)
	c.mu.RUnlock()

	if !fresh {
		if err := c.refresh(ctx, guildID); err != nil {
			return nil, err
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	seen := make(map[string]struct{})
	var groups []string
	for _, roleID := range roleIDs {
		for _, g := range c.cache[roleID] {
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func (c *CachedStore) refresh(ctx context.Context, guildID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.guildID == guildID && time.Now().Before(c.expiresAt) {
		return nil
	}

	mappings, err := c.inner.List(ctx, guildID)
	if err != nil {
		return err
	}

	next := make(map[string][]string)
	for _, m := range mappings {
		next[m.RoleID] = append(next[m.RoleID], m.GroupName)
	}
	c.cache = next
	c.guildID = guildID
	c.expiresAt = time.Now().Add(c.ttl)
	return nil
}
