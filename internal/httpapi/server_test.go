package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yitech/discord-forward-auth/internal/audit"
	"github.com/yitech/discord-forward-auth/internal/config"
	"github.com/yitech/discord-forward-auth/internal/discord"
	"github.com/yitech/discord-forward-auth/internal/hostpolicy"
	"github.com/yitech/discord-forward-auth/internal/httpapi"
	"github.com/yitech/discord-forward-auth/internal/mapping"
	"github.com/yitech/discord-forward-auth/internal/session"
)

type discordMock struct {
	tokenErr  error
	meErr     error
	memberErr error
	user      *discord.User
	member    *discord.Member
	lastCode  string
}

func (d *discordMock) ExchangeCode(_ context.Context, code string) (*discord.TokenResponse, error) {
	d.lastCode = code
	if d.tokenErr != nil {
		return nil, d.tokenErr
	}
	return &discord.TokenResponse{AccessToken: "tok"}, nil
}

func (d *discordMock) GetMe(context.Context, string) (*discord.User, error) {
	if d.meErr != nil {
		return nil, d.meErr
	}
	if d.user == nil {
		return &discord.User{ID: "user1"}, nil
	}
	return d.user, nil
}

func (d *discordMock) GetGuildMember(context.Context, string, string) (*discord.Member, error) {
	if d.memberErr != nil {
		return nil, d.memberErr
	}
	if d.member == nil {
		return &discord.Member{Roles: []string{"role-viewer"}}, nil
	}
	return d.member, nil
}

func testCfg() *config.Config {
	return &config.Config{
		ListenAddr:          ":4181",
		AuthHost:            "auth.example.com",
		DiscordClientID:     "client",
		DiscordClientSecret: "secret",
		DiscordGuildID:      "guild1",
		SessionTTL:          time.Hour,
		CookieName:          "discord_auth_session",
		CookieDomain:        ".example.com",
		CSRFCookieName:      "discord_auth_csrf",
		AdminGroup:          "admin",
		BootstrapAdminRole:  "boot-role",
		HeaderUser:          "X-Auth-User",
		HeaderGroups:        "X-Auth-Groups",
		MappingCacheTTL:     0,
	}
}

func newTestServer(t *testing.T, d *discordMock, maps mapping.Store) (*httpapi.Server, *session.MemoryStore, *audit.MemoryStore) {
	t.Helper()
	return newTestServerWithHosts(t, d, maps, nil)
}

func newTestServerWithHosts(t *testing.T, d *discordMock, maps mapping.Store, hosts hostpolicy.Store) (*httpapi.Server, *session.MemoryStore, *audit.MemoryStore) {
	t.Helper()
	return newTestServerWithWeb(t, d, maps, hosts, nil)
}

func newTestServerWithWeb(
	t *testing.T,
	d *discordMock,
	maps mapping.Store,
	hosts hostpolicy.Store,
	webFS fs.FS,
) (*httpapi.Server, *session.MemoryStore, *audit.MemoryStore) {
	t.Helper()
	if maps == nil {
		maps = mapping.NewMemoryStore()
	}
	if hosts == nil {
		hosts = hostpolicy.NewMemoryStore()
	}
	sess := session.NewMemoryStore()
	aud := audit.NewMemoryStore()
	srv := httpapi.New(testCfg(), sess, maps, hosts, aud, d, webFS, nil)
	return srv, sess, aud
}

func csrfFromLogin(t *testing.T, srv *httpapi.Server, path string, headers map[string]string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	for _, c := range rr.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			return c.Value
		}
	}
	t.Fatal("no csrf cookie")
	return ""
}

func TestForwardAuthUnauthenticatedRedirects(t *testing.T) {
	srv, _, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Uri", "/app/secret")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "discord.com/api/oauth2/authorize") {
		t.Fatalf("location=%s", loc)
	}
	if !strings.Contains(loc, "client_id=client") {
		t.Fatalf("missing client_id: %s", loc)
	}
	if strings.Contains(loc, "prompt=") {
		t.Fatalf("prompt should not be set: %s", loc)
	}
	cookies := rr.Result().Cookies()
	var csrf string
	for _, c := range cookies {
		if c.Name == "discord_auth_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("expected csrf cookie")
	}
}

func TestForwardAuthSubresourceDoesNotMintCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, &discordMock{}, nil)

	// Document navigation mints the CSRF cookie once.
	nav := httptest.NewRequest(http.MethodGet, "/", nil)
	nav.Header.Set("X-Forwarded-Uri", "/")
	nav.Header.Set("X-Forwarded-Host", "app.example.com")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	nav.Header.Set("Sec-Fetch-Dest", "document")
	navRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(navRR, nav)
	if navRR.Code != http.StatusFound {
		t.Fatalf("nav status=%d", navRR.Code)
	}
	var navCSRF string
	for _, c := range navRR.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			navCSRF = c.Value
		}
	}
	if navCSRF == "" {
		t.Fatal("expected csrf from navigation")
	}

	// Parallel sub-resource ForwardAuth must not overwrite that cookie.
	for _, dest := range []string{"style", "script", "image", "empty"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Uri", "/assets/app.css")
		req.Header.Set("X-Forwarded-Host", "app.example.com")
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
		req.Header.Set("Sec-Fetch-Dest", dest)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("dest=%s status=%d", dest, rr.Code)
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == "discord_auth_csrf" {
				t.Fatalf("dest=%s set csrf cookie %q", dest, c.Value)
			}
		}
	}
}

func TestForwardAuthAcceptHTMLWithoutFetchMetadata(t *testing.T) {
	// Without embedded UI, HTML Accept on / still starts OAuth (ForwardAuth fallback).
	srv, _, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestPublicIndexServesGuestPage(t *testing.T) {
	web := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>home</html>")},
	}
	srv, _, _ := newTestServerWithWeb(t, &discordMock{}, nil, nil, web)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "home") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestPublicIndexLoginQueryStartsOAuth(t *testing.T) {
	web := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>home</html>")},
	}
	srv, _, _ := newTestServerWithWeb(t, &discordMock{}, nil, nil, web)

	req := httptest.NewRequest(http.MethodGet, "/?rd=/", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "discord.com/api/oauth2/authorize") {
		t.Fatalf("location=%s", rr.Header().Get("Location"))
	}
}

func TestForwardAuthNonHTMLAcceptWithoutFetchMetadata(t *testing.T) {
	srv, _, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "image/avif,image/webp,image/*")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestForwardAuthValidSession(t *testing.T) {
	srv, store, _ := newTestServer(t, &discordMock{}, nil)
	sess, err := store.Create(context.Background(), "u1", []string{"viewer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Auth-User") != "u1" {
		t.Fatalf("user=%s", rr.Header().Get("X-Auth-User"))
	}
	if rr.Header().Get("X-Auth-Groups") != "viewer" {
		t.Fatalf("groups=%s", rr.Header().Get("X-Auth-Groups"))
	}
}

func TestForwardAuthHostPolicy(t *testing.T) {
	hosts := hostpolicy.NewMemoryStore()
	_ = hosts.Upsert(context.Background(), "grafana.example.com", []string{"engineer"}, "seed")
	srv, store, _ := newTestServerWithHosts(t, &discordMock{}, nil, hosts)

	engineer, err := store.Create(context.Background(), "e1", []string{"engineer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := store.Create(context.Background(), "b1", []string{"bd"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("matching group", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "grafana.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: engineer.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("wrong group", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "grafana.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: bd.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d", rr.Code)
		}
	})

	t.Run("unknown host fail closed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "metabase.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: engineer.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d", rr.Code)
		}
	})

	t.Run("admin bypass", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "metabase.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestForwardAuthHostPolicyWildcard(t *testing.T) {
	hosts := hostpolicy.NewMemoryStore()
	_ = hosts.Upsert(context.Background(), "*.example.com", []string{"engineer"}, "seed")
	_ = hosts.Upsert(context.Background(), "grafana.example.com", []string{"bd"}, "seed")
	srv, store, _ := newTestServerWithHosts(t, &discordMock{}, nil, hosts)

	engineer, err := store.Create(context.Background(), "e1", []string{"engineer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := store.Create(context.Background(), "b1", []string{"bd"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wildcard match", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "wiki.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: engineer.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("exact beats wildcard", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "grafana.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: engineer.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d", rr.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "grafana.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: bd.ID})
		rr = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("deep subdomain no match", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Host", "a.b.example.com")
		req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: engineer.ID})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d", rr.Code)
		}
	})
}

func TestAdminHostPolicies(t *testing.T) {
	hosts := hostpolicy.NewMemoryStore()
	srv, store, aud := newTestServerWithHosts(t, &discordMock{}, nil, hosts)
	admin, _ := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)
	viewer, _ := store.Create(context.Background(), "v1", []string{"viewer"}, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/api/host-policies", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: viewer.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d", rr.Code)
	}

	badBody := `{"host":"*","required_groups":["engineer"]}`
	req = withOrigin(httptest.NewRequest(http.MethodPost, "/api/host-policies", strings.NewReader(badBody)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid pattern status=%d", rr.Code)
	}

	body := `{"host":"Grafana.Example.Com","required_groups":["engineer"," bd "]}`
	req = withOrigin(httptest.NewRequest(http.MethodPost, "/api/host-policies", strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upsert status=%d body=%s", rr.Code, rr.Body.String())
	}

	wildBody := `{"host":"*.apps.example.com","required_groups":["engineer"]}`
	req = withOrigin(httptest.NewRequest(http.MethodPost, "/api/host-policies", strings.NewReader(wildBody)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("wildcard upsert status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/host-policies", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d", rr.Code)
	}
	var list []hostpolicy.Policy
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list=%v", list)
	}
	byHost := map[string]hostpolicy.Policy{}
	for _, p := range list {
		byHost[p.Host] = p
	}
	if p, ok := byHost["grafana.example.com"]; !ok || len(p.RequiredGroups) != 2 {
		t.Fatalf("exact policy=%v", byHost["grafana.example.com"])
	}
	if p, ok := byHost["*.apps.example.com"]; !ok || len(p.RequiredGroups) != 1 {
		t.Fatalf("wildcard policy=%v", byHost["*.apps.example.com"])
	}

	req = withOrigin(httptest.NewRequest(http.MethodDelete, "/api/host-policies?host=grafana.example.com", nil))
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}

	events, total, err := aud.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("audit total=%d", total)
	}
	if events[0].Action != audit.ActionHostPolicyDelete ||
		events[1].Action != audit.ActionHostPolicyUpsert ||
		events[2].Action != audit.ActionHostPolicyUpsert {
		t.Fatalf("actions=%s,%s,%s", events[0].Action, events[1].Action, events[2].Action)
	}
}

func TestForwardAuthRevokedSession(t *testing.T) {
	srv, store, _ := newTestServer(t, &discordMock{}, nil)
	sess, err := store.Create(context.Background(), "u1", []string{"viewer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Revoke(context.Background(), sess.ID)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestOAuthCallbackCSRFMismatch(t *testing.T) {
	srv, _, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: "other"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid state") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestOAuthCallbackMissingCSRFCookie(t *testing.T) {
	srv, _, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state=xyz", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "login session expired or already used") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestOAuthCallbackNotMember(t *testing.T) {
	d := &discordMock{
		user:      &discord.User{ID: "user1", Username: "alice"},
		memberErr: discord.ErrNotGuildMember,
	}
	srv, _, aud := newTestServer(t, d, nil)
	state := csrfFromLogin(t, srv, "/?rd=/admin/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	events, total, err := aud.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || events[0].Action != audit.ActionLoginDenied {
		t.Fatalf("audit=%v total=%d", events, total)
	}
	var details map[string]any
	if err := json.Unmarshal(events[0].Details, &details); err != nil {
		t.Fatal(err)
	}
	if details["reason"] != "not_guild_member" || details["ip"] != "203.0.113.50" {
		t.Fatalf("details=%v", details)
	}
}

func TestOAuthCallbackNoGroups(t *testing.T) {
	d := &discordMock{member: &discord.Member{Roles: []string{"unmapped"}}}
	srv, _, aud := newTestServer(t, d, mapping.NewMemoryStore())
	state := csrfFromLogin(t, srv, "/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	events, total, err := aud.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || events[0].Action != audit.ActionLoginDenied {
		t.Fatalf("audit=%v total=%d", events, total)
	}
	var details map[string]any
	if err := json.Unmarshal(events[0].Details, &details); err != nil {
		t.Fatal(err)
	}
	if details["reason"] != "no_authorized_groups" {
		t.Fatalf("details=%v", details)
	}
}

func TestOAuthCallbackAPIFailureFailClosed(t *testing.T) {
	d := &discordMock{tokenErr: errors.New("discord 500")}
	srv, _, _ := newTestServer(t, d, nil)
	state := csrfFromLogin(t, srv, "/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestOAuthCallbackSuccess(t *testing.T) {
	maps := mapping.NewMemoryStore()
	_ = maps.Upsert(context.Background(), "guild1", "role-viewer", "viewer", "seed")
	d := &discordMock{
		user:   &discord.User{ID: "user1", Username: "alice"},
		member: &discord.Member{Roles: []string{"role-viewer"}},
	}
	srv, _, aud := newTestServer(t, d, maps)
	state := csrfFromLogin(t, srv, "/?rd=/admin/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.RemoteAddr = "10.0.0.9:4000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.9")
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "/admin/" {
		t.Fatalf("location=%s", rr.Header().Get("Location"))
	}
	var sid string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "discord_auth_session" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("expected session cookie")
	}

	events, total, err := aud.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || events[0].Action != audit.ActionLoginSuccess || events[0].Actor != "user1" {
		t.Fatalf("audit=%v total=%d", events, total)
	}
	var details map[string]any
	if err := json.Unmarshal(events[0].Details, &details); err != nil {
		t.Fatal(err)
	}
	if details["ip"] != "198.51.100.7" || details["username"] != "alice" {
		t.Fatalf("details=%v", details)
	}
	groups, ok := details["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "viewer" {
		t.Fatalf("groups=%v", details["groups"])
	}
}

// Direct AUTH_HOST login without an app return target lands on the public index.
func TestOAuthCallbackDirectAuthHostRootReturnsHome(t *testing.T) {
	maps := mapping.NewMemoryStore()
	_ = maps.Upsert(context.Background(), "guild1", "role-viewer", "viewer", "seed")
	d := &discordMock{member: &discord.Member{Roles: []string{"role-viewer"}}}
	srv, _, _ := newTestServer(t, d, maps)
	state := csrfFromLogin(t, srv, "/?rd=/", map[string]string{
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	})

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "/" {
		t.Fatalf("location=%s", rr.Header().Get("Location"))
	}
}

func TestOAuthCallbackRedirectsToAppHost(t *testing.T) {
	maps := mapping.NewMemoryStore()
	_ = maps.Upsert(context.Background(), "guild1", "role-viewer", "viewer", "seed")
	d := &discordMock{member: &discord.Member{Roles: []string{"role-viewer"}}}
	srv, _, _ := newTestServer(t, d, maps)
	state := csrfFromLogin(t, srv, "/", map[string]string{
		"X-Forwarded-Uri":  "/dashboard",
		"X-Forwarded-Host": "app.example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "https://app.example.com/dashboard" {
		t.Fatalf("location=%s", rr.Header().Get("Location"))
	}
}

func TestOAuthCallbackBootstrapAdmin(t *testing.T) {
	d := &discordMock{member: &discord.Member{Roles: []string{"boot-role"}}}
	srv, _, _ := newTestServer(t, d, mapping.NewMemoryStore())
	state := csrfFromLogin(t, srv, "/?rd=/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "/" {
		t.Fatalf("location=%s", rr.Header().Get("Location"))
	}
}

func TestLogoutRevokes(t *testing.T) {
	srv, store, aud := newTestServer(t, &discordMock{}, nil)
	sess, err := store.Create(context.Background(), "u1", []string{"viewer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/_oauth/logout", nil)
	req.Header.Set("X-Real-IP", "192.0.2.10")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if _, err := store.GetValid(context.Background(), sess.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected revoked, err=%v", err)
	}
	events, total, err := aud.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || events[0].Action != audit.ActionLogout || events[0].Actor != "u1" {
		t.Fatalf("audit=%v total=%d", events, total)
	}
	var details map[string]any
	if err := json.Unmarshal(events[0].Details, &details); err != nil {
		t.Fatal(err)
	}
	if details["ip"] != "192.0.2.10" {
		t.Fatalf("details=%v", details)
	}
}

func withOrigin(req *http.Request) *http.Request {
	req.Header.Set("Origin", "https://auth.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return req
}

func TestAdminMappingsAuthz(t *testing.T) {
	maps := mapping.NewMemoryStore()
	srv, store, aud := newTestServer(t, &discordMock{}, maps)

	viewer, _ := store.Create(context.Background(), "v1", []string{"viewer"}, time.Hour)
	admin, _ := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: viewer.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d", rr.Code)
	}

	body := `{"role_id":"r1","group_name":"operator"}`
	req = withOrigin(httptest.NewRequest(http.MethodPost, "/api/mappings", strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upsert status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d", rr.Code)
	}
	var list []mapping.Mapping
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RoleID != "r1" {
		t.Fatalf("list=%v", list)
	}

	req = withOrigin(httptest.NewRequest(http.MethodDelete, "/api/mappings?role_id=r1&group_name=operator", nil))
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}

	events, total, err := aud.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("audit total=%d", total)
	}
	if events[0].Action != audit.ActionMappingDelete || events[1].Action != audit.ActionMappingUpsert {
		t.Fatalf("actions=%s,%s", events[0].Action, events[1].Action)
	}
	if events[0].Actor != "a1" || events[1].Actor != "a1" {
		t.Fatalf("actors=%s,%s", events[0].Actor, events[1].Actor)
	}
}

func TestListAuditPagination(t *testing.T) {
	srv, store, aud := newTestServer(t, &discordMock{}, nil)
	admin, _ := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)
	viewer, _ := store.Create(context.Background(), "v1", []string{"viewer"}, time.Hour)

	for i := 0; i < 5; i++ {
		if err := aud.Append(context.Background(), "a1", audit.ActionMappingUpsert, "r", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit?limit=2&offset=0", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: viewer.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit?limit=2&offset=2", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var page audit.Page
	if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || page.Limit != 2 || page.Offset != 2 || len(page.Items) != 2 {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].ID != 3 || page.Items[1].ID != 2 {
		t.Fatalf("ids=%d,%d", page.Items[0].ID, page.Items[1].ID)
	}

	// Invalid / oversized params are clamped.
	req = httptest.NewRequest(http.MethodGet, "/api/audit?limit=999&offset=-3", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clamp status=%d", rr.Code)
	}
	if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Limit != 100 || page.Offset != 0 || len(page.Items) != 5 {
		t.Fatalf("clamped page=%+v", page)
	}
}

func TestAdminMutationRejectsCrossSiteOrigin(t *testing.T) {
	srv, store, _ := newTestServer(t, &discordMock{}, nil)
	admin, _ := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)
	body := `{"role_id":"r1","group_name":"operator"}`
	req := httptest.NewRequest(http.MethodPost, "/api/mappings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestRevokeUserSessions(t *testing.T) {
	srv, store, _ := newTestServer(t, &discordMock{}, nil)
	admin, _ := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)
	target, _ := store.Create(context.Background(), "victim", []string{"viewer"}, time.Hour)

	body := `{"discord_user":"victim"}`
	req := withOrigin(httptest.NewRequest(http.MethodPost, "/api/sessions/revoke", strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := store.GetValid(context.Background(), target.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected target revoked, err=%v", err)
	}

	// ForwardAuth should redirect revoked user
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: target.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("forwardauth status=%d", rr.Code)
	}
}

func TestMeUnauthorized(t *testing.T) {
	srv, _, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	_, _ = io.Copy(io.Discard, rr.Body)
}
