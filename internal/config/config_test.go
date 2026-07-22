package config_test

import (
	"testing"

	"github.com/yitech/discord-forward-auth/internal/config"
)

func TestLoadAdjustsHostCookiesWhenDomainSet(t *testing.T) {
	t.Setenv("AUTH_HOST", "auth.example.com")
	t.Setenv("DISCORD_CLIENT_ID", "id")
	t.Setenv("DISCORD_CLIENT_SECRET", "secret")
	t.Setenv("DISCORD_GUILD_ID", "guild")
	t.Setenv("BOOTSTRAP_ADMIN_ROLE_ID", "role")
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("COOKIE_DOMAIN", ".example.com")
	t.Setenv("COOKIE_NAME", "__Host-discord_auth_session")
	t.Setenv("CSRF_COOKIE_NAME", "__Host-discord_auth_csrf")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "discord_auth_session" {
		t.Fatalf("cookie name=%q", cfg.CookieName)
	}
	if cfg.CSRFCookieName != "discord_auth_csrf" {
		t.Fatalf("csrf name=%q", cfg.CSRFCookieName)
	}
	if cfg.RedirectURI() != "https://auth.example.com/_oauth" {
		t.Fatalf("redirect=%q", cfg.RedirectURI())
	}
}

func TestLoadMissingRequired(t *testing.T) {
	for _, k := range []string{
		"AUTH_HOST", "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET",
		"DISCORD_GUILD_ID", "BOOTSTRAP_ADMIN_ROLE_ID", "DATABASE_URL",
	} {
		t.Setenv(k, "")
	}
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error")
	}
}
