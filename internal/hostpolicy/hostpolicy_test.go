package hostpolicy_test

import (
	"context"
	"testing"

	"github.com/yitech/discord-forward-auth/internal/hostpolicy"
)

func TestAllowed(t *testing.T) {
	policy := &hostpolicy.Policy{Host: "grafana.example.com", RequiredGroups: []string{"engineer"}}

	cases := []struct {
		name          string
		host          string
		authHost      string
		adminGroup    string
		sessionGroups []string
		policy        *hostpolicy.Policy
		hasPolicy     bool
		want          bool
	}{
		{name: "admin bypass", host: "grafana.example.com", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"admin"}, hasPolicy: false, want: true},
		{name: "empty host", host: "", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"viewer"}, hasPolicy: false, want: true},
		{name: "auth host", host: "auth.example.com", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"viewer"}, hasPolicy: false, want: true},
		{name: "matching group", host: "grafana.example.com", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"engineer"}, policy: policy, hasPolicy: true, want: true},
		{name: "wrong group", host: "grafana.example.com", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"bd"}, policy: policy, hasPolicy: true, want: false},
		{name: "unknown host fail closed", host: "grafana.example.com", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"engineer"}, hasPolicy: false, want: false},
		{name: "any of required", host: "wiki.example.com", authHost: "auth.example.com", adminGroup: "admin", sessionGroups: []string{"bd"}, policy: &hostpolicy.Policy{RequiredGroups: []string{"engineer", "bd"}}, hasPolicy: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostpolicy.Allowed(tc.host, tc.authHost, tc.adminGroup, tc.sessionGroups, tc.policy, tc.hasPolicy)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestMemoryStoreCRUD(t *testing.T) {
	s := hostpolicy.NewMemoryStore()
	ctx := context.Background()

	if err := s.Upsert(ctx, "Grafana.Example.Com:443", []string{" Engineer ", "Engineer", "bd"}, "a1"); err != nil {
		t.Fatal(err)
	}
	p, err := s.Get(ctx, "grafana.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "grafana.example.com" {
		t.Fatalf("host=%s", p.Host)
	}
	if len(p.RequiredGroups) != 2 || p.RequiredGroups[0] != "Engineer" || p.RequiredGroups[1] != "bd" {
		t.Fatalf("groups=%v", p.RequiredGroups)
	}

	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	if err := s.Delete(ctx, "grafana.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "grafana.example.com"); err != hostpolicy.ErrNotFound {
		t.Fatalf("err=%v", err)
	}
}
