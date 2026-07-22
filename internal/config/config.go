package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr          string
	AuthHost            string
	DiscordClientID     string
	DiscordClientSecret string
	DiscordGuildID      string
	SessionTTL          time.Duration
	CookieName          string
	CookieDomain        string
	CSRFCookieName      string
	DatabaseURL         string
	AdminGroup          string
	BootstrapAdminRole  string
	MappingCacheTTL     time.Duration
	HeaderUser          string
	HeaderGroups        string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:          getenv("LISTEN_ADDR", ":4181"),
		AuthHost:            os.Getenv("AUTH_HOST"),
		DiscordClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		DiscordClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		DiscordGuildID:      os.Getenv("DISCORD_GUILD_ID"),
		CookieName:          getenv("COOKIE_NAME", "__Host-discord_auth_session"),
		CookieDomain:        os.Getenv("COOKIE_DOMAIN"),
		CSRFCookieName:      getenv("CSRF_COOKIE_NAME", "__Host-discord_auth_csrf"),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		AdminGroup:          getenv("ADMIN_GROUP", "admin"),
		BootstrapAdminRole:  os.Getenv("BOOTSTRAP_ADMIN_ROLE_ID"),
		HeaderUser:          getenv("HEADER_USER", "X-Auth-User"),
		HeaderGroups:        getenv("HEADER_GROUPS", "X-Auth-Groups"),
	}

	sessionTTL, err := getenvDurationSeconds("SESSION_TTL", 1800)
	if err != nil {
		return nil, err
	}
	cfg.SessionTTL = sessionTTL

	mappingTTL, err := getenvDurationSeconds("MAPPING_CACHE_TTL", 30)
	if err != nil {
		return nil, err
	}
	cfg.MappingCacheTTL = mappingTTL

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// __Host- cookies cannot set Domain; adjust cookie names when CookieDomain is set.
	if cfg.CookieDomain != "" {
		if strings.HasPrefix(cfg.CookieName, "__Host-") {
			cfg.CookieName = strings.TrimPrefix(cfg.CookieName, "__Host-")
		}
		if strings.HasPrefix(cfg.CSRFCookieName, "__Host-") {
			cfg.CSRFCookieName = strings.TrimPrefix(cfg.CSRFCookieName, "__Host-")
		}
	}

	return cfg, nil
}

func (c *Config) validate() error {
	required := map[string]string{
		"AUTH_HOST":             c.AuthHost,
		"DISCORD_CLIENT_ID":     c.DiscordClientID,
		"DISCORD_CLIENT_SECRET": c.DiscordClientSecret,
		"DISCORD_GUILD_ID":      c.DiscordGuildID,
		"DATABASE_URL":          c.DatabaseURL,
		"BOOTSTRAP_ADMIN_ROLE_ID": c.BootstrapAdminRole,
	}
	var missing []string
	for k, v := range required {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("SESSION_TTL must be > 0")
	}
	if c.MappingCacheTTL < 0 {
		return fmt.Errorf("MAPPING_CACHE_TTL must be >= 0")
	}
	return nil
}

func (c *Config) RedirectURI() string {
	return "https://" + c.AuthHost + "/_oauth"
}

func (c *Config) AuthorizeURL() string {
	return "https://discord.com/api/oauth2/authorize"
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvDurationSeconds(key string, fallback int) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return time.Duration(fallback) * time.Second, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return time.Duration(n) * time.Second, nil
}
