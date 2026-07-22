package hostpolicy

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/yitech/discord-forward-auth/internal/authz"
	"github.com/yitech/discord-forward-auth/internal/config"
)

var ErrNotFound = errors.New("host policy not found")

var ErrInvalid = errors.New("host and required_groups required")

type Policy struct {
	Host           string    `json:"host"`
	RequiredGroups []string  `json:"required_groups"`
	UpdatedAt      time.Time `json:"updated_at"`
	UpdatedBy      *string   `json:"updated_by,omitempty"`
}

type Store interface {
	List(ctx context.Context) ([]Policy, error)
	Get(ctx context.Context, host string) (*Policy, error)
	Upsert(ctx context.Context, host string, requiredGroups []string, updatedBy string) error
	Delete(ctx context.Context, host string) error
}

// NormalizeGroups trims, dedupes, and sorts group names (case preserved).
func NormalizeGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	var out []string
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Allowed reports whether sessionGroups may access host.
// Empty host or AUTH_HOST skips host ACL. Admin group always bypasses.
// When hasPolicy is false for any other host, access is denied (fail-closed).
func Allowed(host, authHost, adminGroup string, sessionGroups []string, policy *Policy, hasPolicy bool) bool {
	if authz.HasGroup(sessionGroups, adminGroup) {
		return true
	}
	host = config.NormalizeHost(host)
	if host == "" || host == config.NormalizeHost(authHost) {
		return true
	}
	if !hasPolicy || policy == nil {
		return false
	}
	for _, g := range sessionGroups {
		if authz.HasGroup(policy.RequiredGroups, g) {
			return true
		}
	}
	return false
}
