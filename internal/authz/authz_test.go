package authz_test

import (
	"context"
	"testing"

	"github.com/yitech/discord-forward-auth/internal/authz"
	"github.com/yitech/discord-forward-auth/internal/mapping"
)

type mapStub struct {
	byRole map[string][]string
	err    error
}

func (m *mapStub) List(context.Context, string) ([]mapping.Mapping, error) { return nil, nil }
func (m *mapStub) Upsert(context.Context, string, string, string, string) error {
	return nil
}
func (m *mapStub) Delete(context.Context, string, string, string) error { return nil }
func (m *mapStub) InvalidateCache()                                    {}
func (m *mapStub) GroupsForRoles(_ context.Context, _ string, roleIDs []string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, id := range roleIDs {
		for _, g := range m.byRole[id] {
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}
			out = append(out, g)
		}
	}
	return out, nil
}

func TestGroupsForRolesEmpty(t *testing.T) {
	r := &authz.Resolver{
		Mappings:           &mapStub{byRole: map[string][]string{}},
		GuildID:            "g1",
		BootstrapAdminRole: "boot",
		AdminGroup:         "admin",
	}
	groups, err := r.GroupsForRoles(context.Background(), []string{"unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected empty, got %v", groups)
	}
}

func TestGroupsForRolesMultiHit(t *testing.T) {
	r := &authz.Resolver{
		Mappings: &mapStub{byRole: map[string][]string{
			"r1": {"viewer"},
			"r2": {"operator", "viewer"},
		}},
		GuildID:    "g1",
		AdminGroup: "admin",
	}
	groups, err := r.GroupsForRoles(context.Background(), []string{"r1", "r2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0] != "operator" || groups[1] != "viewer" {
		t.Fatalf("unexpected groups: %v", groups)
	}
}

func TestBootstrapAdminRole(t *testing.T) {
	r := &authz.Resolver{
		Mappings:           &mapStub{byRole: map[string][]string{}},
		GuildID:            "g1",
		BootstrapAdminRole: "boot",
		AdminGroup:         "admin",
	}
	groups, err := r.GroupsForRoles(context.Background(), []string{"boot", "other"})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != "admin" {
		t.Fatalf("expected [admin], got %v", groups)
	}
}

func TestHasGroup(t *testing.T) {
	if !authz.HasGroup([]string{"a", "b"}, "b") {
		t.Fatal("expected true")
	}
	if authz.HasGroup([]string{"a"}, "admin") {
		t.Fatal("expected false")
	}
}
