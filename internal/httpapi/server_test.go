package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yitech/discord-forward-auth/internal/config"
	"github.com/yitech/discord-forward-auth/internal/discord"
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

func newTestServer(t *testing.T, d *discordMock, maps mapping.Store) (*httpapi.Server, *session.MemoryStore) {
	t.Helper()
	if maps == nil {
		maps = mapping.NewMemoryStore()
	}
	sess := session.NewMemoryStore()
	srv := httpapi.New(testCfg(), sess, maps, d, nil, nil)
	return srv, sess
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
	srv, _ := newTestServer(t, &discordMock{}, nil)
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
	srv, _ := newTestServer(t, &discordMock{}, nil)

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
	srv, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestForwardAuthNonHTMLAcceptWithoutFetchMetadata(t *testing.T) {
	srv, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "image/avif,image/webp,image/*")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestForwardAuthValidSession(t *testing.T) {
	srv, store := newTestServer(t, &discordMock{}, nil)
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

func TestForwardAuthRevokedSession(t *testing.T) {
	srv, store := newTestServer(t, &discordMock{}, nil)
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
	srv, _ := newTestServer(t, &discordMock{}, nil)
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
	srv, _ := newTestServer(t, &discordMock{}, nil)
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
	d := &discordMock{memberErr: discord.ErrNotGuildMember}
	srv, _ := newTestServer(t, d, nil)
	state := csrfFromLogin(t, srv, "/?rd=/admin/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestOAuthCallbackNoGroups(t *testing.T) {
	d := &discordMock{member: &discord.Member{Roles: []string{"unmapped"}}}
	srv, _ := newTestServer(t, d, mapping.NewMemoryStore())
	state := csrfFromLogin(t, srv, "/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestOAuthCallbackAPIFailureFailClosed(t *testing.T) {
	d := &discordMock{tokenErr: errors.New("discord 500")}
	srv, _ := newTestServer(t, d, nil)
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
	d := &discordMock{member: &discord.Member{Roles: []string{"role-viewer"}}}
	srv, _ := newTestServer(t, d, maps)
	state := csrfFromLogin(t, srv, "/?rd=/admin/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
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
}

func TestOAuthCallbackRedirectsToAppHost(t *testing.T) {
	maps := mapping.NewMemoryStore()
	_ = maps.Upsert(context.Background(), "guild1", "role-viewer", "viewer", "seed")
	d := &discordMock{member: &discord.Member{Roles: []string{"role-viewer"}}}
	srv, _ := newTestServer(t, d, maps)
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
	srv, _ := newTestServer(t, d, mapping.NewMemoryStore())
	state := csrfFromLogin(t, srv, "/", nil)

	req := httptest.NewRequest(http.MethodGet, "/_oauth?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_csrf", Value: state})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLogoutRevokes(t *testing.T) {
	srv, store := newTestServer(t, &discordMock{}, nil)
	sess, err := store.Create(context.Background(), "u1", []string{"viewer"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/_oauth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if _, err := store.GetValid(context.Background(), sess.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected revoked, err=%v", err)
	}
}

func withOrigin(req *http.Request) *http.Request {
	req.Header.Set("Origin", "https://auth.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return req
}

func TestAdminMappingsAuthz(t *testing.T) {
	maps := mapping.NewMemoryStore()
	srv, store := newTestServer(t, &discordMock{}, maps)

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
}

func TestAdminMutationRejectsCrossSiteOrigin(t *testing.T) {
	srv, store := newTestServer(t, &discordMock{}, nil)
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
	srv, store := newTestServer(t, &discordMock{}, nil)
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
	srv, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	_, _ = io.Copy(io.Discard, rr.Body)
}
