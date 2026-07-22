package config_test

import (
	"testing"

	"github.com/yitech/discord-forward-auth/internal/config"
)

func requiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_HOST", "auth.example.com")
	t.Setenv("DISCORD_CLIENT_ID", "id")
	t.Setenv("DISCORD_CLIENT_SECRET", "secret")
	t.Setenv("DISCORD_GUILD_ID", "guild")
	t.Setenv("BOOTSTRAP_ADMIN_ROLE_ID", "role")
	t.Setenv("DATABASE_URL", "postgres://x")
}

func TestLoadRequiresCookieDomain(t *testing.T) {
	requiredEnv(t)
	t.Setenv("COOKIE_DOMAIN", "")
	t.Setenv("SINGLE_HOST", "")
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error when COOKIE_DOMAIN empty")
	}
}

func TestLoadSingleHostAllowsEmptyCookieDomain(t *testing.T) {
	requiredEnv(t)
	t.Setenv("COOKIE_DOMAIN", "")
	t.Setenv("SINGLE_HOST", "true")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SingleHost {
		t.Fatal("expected SingleHost")
	}
	if cfg.CookieName != "__Host-discord_auth_session" {
		t.Fatalf("cookie name=%q", cfg.CookieName)
	}
}

func TestLoadDowngradesHostCookiesToSecure(t *testing.T) {
	requiredEnv(t)
	t.Setenv("COOKIE_DOMAIN", ".example.com")
	t.Setenv("COOKIE_NAME", "__Host-discord_auth_session")
	t.Setenv("CSRF_COOKIE_NAME", "__Host-discord_auth_csrf")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "__Secure-discord_auth_session" {
		t.Fatalf("cookie name=%q", cfg.CookieName)
	}
	if cfg.CSRFCookieName != "__Secure-discord_auth_csrf" {
		t.Fatalf("csrf name=%q", cfg.CSRFCookieName)
	}
	if cfg.RedirectURI() != "https://auth.example.com/_oauth" {
		t.Fatalf("redirect=%q", cfg.RedirectURI())
	}
}

func TestLoadRejectsCookieDomainWithSingleHost(t *testing.T) {
	requiredEnv(t)
	t.Setenv("COOKIE_DOMAIN", ".example.com")
	t.Setenv("SINGLE_HOST", "true")
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
}

func TestHostAllowed(t *testing.T) {
	requiredEnv(t)
	t.Setenv("COOKIE_DOMAIN", ".example.com")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"auth.example.com": true,
		"app.example.com":  true,
		"example.com":      true,
		"evil.com":         false,
		"example.com.evil": false,
		"":                 false,
	}
	for host, want := range cases {
		if got := cfg.HostAllowed(host); got != want {
			t.Fatalf("HostAllowed(%q)=%v want %v", host, got, want)
		}
	}
}

func TestLoadMissingRequired(t *testing.T) {
	for _, k := range []string{
		"AUTH_HOST", "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET",
		"DISCORD_GUILD_ID", "BOOTSTRAP_ADMIN_ROLE_ID", "DATABASE_URL",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("SINGLE_HOST", "true")
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error")
	}
}
