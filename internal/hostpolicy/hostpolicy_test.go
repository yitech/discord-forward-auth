package hostpolicy_test

import (
	"context"
	"errors"
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

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{pattern: "grafana.example.com", host: "grafana.example.com", want: true},
		{pattern: "grafana.example.com", host: "Grafana.Example.Com", want: true},
		{pattern: "grafana.example.com", host: "other.example.com", want: false},
		{pattern: "*.example.com", host: "grafana.example.com", want: true},
		{pattern: "*.example.com", host: "example.com", want: false},
		{pattern: "*.example.com", host: "a.b.example.com", want: false},
		{pattern: "*.b.example.com", host: "a.b.example.com", want: true},
		{pattern: "*.b.example.com", host: "b.example.com", want: false},
		{pattern: "*.example.com", host: "", want: false},
		{pattern: "", host: "grafana.example.com", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"_"+tc.host, func(t *testing.T) {
			if got := hostpolicy.MatchHost(tc.pattern, tc.host); got != tc.want {
				t.Fatalf("MatchHost(%q, %q)=%v want %v", tc.pattern, tc.host, got, tc.want)
			}
		})
	}
}

func TestValidatePattern(t *testing.T) {
	ok := []string{"grafana.example.com", "*.example.com", "*.apps.example.com", "Grafana.Example.Com:443"}
	for _, p := range ok {
		if err := hostpolicy.ValidatePattern(p); err != nil {
			t.Fatalf("ValidatePattern(%q)=%v", p, err)
		}
	}
	bad := []string{"*", "*.*", "foo.*.com", "example.com.*", "localhost", "-bad.example.com", "a_b.example.com", ""}
	for _, p := range bad {
		if err := hostpolicy.ValidatePattern(p); !errors.Is(err, hostpolicy.ErrInvalidPattern) {
			t.Fatalf("ValidatePattern(%q)=%v want ErrInvalidPattern", p, err)
		}
	}
}

func TestBestMatchSpecificity(t *testing.T) {
	policies := []hostpolicy.Policy{
		{Host: "*.example.com", RequiredGroups: []string{"all"}},
		{Host: "*.apps.example.com", RequiredGroups: []string{"apps"}},
		{Host: "grafana.apps.example.com", RequiredGroups: []string{"exact"}},
	}

	cases := []struct {
		host string
		want string
	}{
		{host: "grafana.apps.example.com", want: "grafana.apps.example.com"},
		{host: "wiki.apps.example.com", want: "*.apps.example.com"},
		{host: "metabase.example.com", want: "*.example.com"},
		{host: "a.b.example.com", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got, ok := hostpolicy.BestMatch(tc.host, policies)
			if tc.want == "" {
				if ok {
					t.Fatalf("unexpected match %q", got.Host)
				}
				return
			}
			if !ok || got.Host != tc.want {
				t.Fatalf("got=%v ok=%v want %q", got, ok, tc.want)
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

func TestMemoryStoreWildcardMatch(t *testing.T) {
	s := hostpolicy.NewMemoryStore()
	ctx := context.Background()

	if err := s.Upsert(ctx, "*.example.com", []string{"engineer"}, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, "grafana.example.com", []string{"bd"}, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, "*", []string{"nope"}, "a1"); !errors.Is(err, hostpolicy.ErrInvalidPattern) {
		t.Fatalf("upsert *=%v", err)
	}

	p, err := s.Match(ctx, "wiki.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "*.example.com" || p.RequiredGroups[0] != "engineer" {
		t.Fatalf("match=%+v", p)
	}

	p, err = s.Match(ctx, "grafana.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "grafana.example.com" || p.RequiredGroups[0] != "bd" {
		t.Fatalf("exact match=%+v", p)
	}

	if _, err := s.Match(ctx, "a.b.example.com"); err != hostpolicy.ErrNotFound {
		t.Fatalf("deep subdomain err=%v", err)
	}
}
