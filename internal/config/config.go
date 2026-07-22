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
	SingleHost          bool
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:          getenv("LISTEN_ADDR", ":4181"),
		AuthHost:            os.Getenv("AUTH_HOST"),
		DiscordClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		DiscordClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		DiscordGuildID:      os.Getenv("DISCORD_GUILD_ID"),
		CookieName:          getenv("COOKIE_NAME", "__Host-discord_auth_session"),
		CookieDomain:        strings.TrimSpace(os.Getenv("COOKIE_DOMAIN")),
		CSRFCookieName:      getenv("CSRF_COOKIE_NAME", "__Host-discord_auth_csrf"),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		AdminGroup:          getenv("ADMIN_GROUP", "admin"),
		BootstrapAdminRole:  os.Getenv("BOOTSTRAP_ADMIN_ROLE_ID"),
		HeaderUser:          getenv("HEADER_USER", "X-Auth-User"),
		HeaderGroups:        getenv("HEADER_GROUPS", "X-Auth-Groups"),
		SingleHost:          getenvBool("SINGLE_HOST", false),
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

	// __Host- cookies cannot set Domain; downgrade to __Secure- when sharing a parent domain.
	if cfg.CookieDomain != "" {
		cfg.CookieName = secureCookieName(cfg.CookieName)
		cfg.CSRFCookieName = secureCookieName(cfg.CSRFCookieName)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	required := map[string]string{
		"AUTH_HOST":               c.AuthHost,
		"DISCORD_CLIENT_ID":       c.DiscordClientID,
		"DISCORD_CLIENT_SECRET":   c.DiscordClientSecret,
		"DISCORD_GUILD_ID":        c.DiscordGuildID,
		"DATABASE_URL":            c.DatabaseURL,
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
	if c.CookieDomain == "" && !c.SingleHost {
		return fmt.Errorf("COOKIE_DOMAIN is required for multi-host deployments (auth host + protected apps); set COOKIE_DOMAIN=.example.com or SINGLE_HOST=true if AUTH_HOST is the only protected host")
	}
	if c.CookieDomain != "" && c.SingleHost {
		return fmt.Errorf("COOKIE_DOMAIN and SINGLE_HOST=true are mutually exclusive")
	}
	if c.CookieDomain != "" {
		d := strings.TrimPrefix(c.CookieDomain, ".")
		if d == "" || strings.Contains(d, "/") || strings.Contains(d, ":") {
			return fmt.Errorf("COOKIE_DOMAIN must be a parent domain like .example.com")
		}
	}
	return nil
}

func (c *Config) RedirectURI() string {
	return "https://" + c.AuthHost + "/_oauth"
}

func (c *Config) AuthorizeURL() string {
	return "https://discord.com/api/oauth2/authorize"
}

// HostAllowed reports whether a return host may receive the post-login redirect.
func (c *Config) HostAllowed(host string) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	if host == NormalizeHost(c.AuthHost) {
		return true
	}
	if c.CookieDomain == "" {
		return false
	}
	domain := strings.TrimPrefix(strings.ToLower(c.CookieDomain), ".")
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// Strip port (X-Forwarded-Host may include it).
	if h, _, ok := strings.Cut(host, ":"); ok {
		// Keep IPv6 bracket form out of scope; hosts here are DNS names.
		if !strings.HasPrefix(host, "[") {
			return h
		}
	}
	return host
}

func secureCookieName(name string) string {
	name = strings.TrimPrefix(name, "__Host-")
	name = strings.TrimPrefix(name, "__Secure-")
	return "__Secure-" + name
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
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
