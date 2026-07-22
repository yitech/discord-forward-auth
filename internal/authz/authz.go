package authz

import (
	"context"
	"sort"

	"github.com/yitech/discord-forward-auth/internal/mapping"
)

type Resolver struct {
	Mappings           mapping.Store
	GuildID            string
	BootstrapAdminRole string
	AdminGroup         string
}

func (r *Resolver) GroupsForRoles(ctx context.Context, roleIDs []string) ([]string, error) {
	groups, err := r.Mappings.GroupsForRoles(ctx, r.GuildID, roleIDs)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		seen[g] = struct{}{}
	}

	if r.BootstrapAdminRole != "" {
		for _, roleID := range roleIDs {
			if roleID == r.BootstrapAdminRole {
				seen[r.AdminGroup] = struct{}{}
				break
			}
		}
	}

	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

func HasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}
