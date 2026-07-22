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

func TestForwardAuthUnauthenticatedRedirects(t *testing.T) {
	srv, _ := newTestServer(t, &discordMock{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Uri", "/app/secret")
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
}

func TestOAuthCallbackNotMember(t *testing.T) {
	d := &discordMock{memberErr: discord.ErrNotGuildMember}
	srv, _ := newTestServer(t, d, nil)

	// Obtain a valid state via login redirect.
	login := httptest.NewRequest(http.MethodGet, "/?rd=/admin/", nil)
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, login)
	var state string
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			state = c.Value
		}
	}
	if state == "" {
		t.Fatal("no state")
	}

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

	login := httptest.NewRequest(http.MethodGet, "/", nil)
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, login)
	var state string
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			state = c.Value
		}
	}

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

	login := httptest.NewRequest(http.MethodGet, "/", nil)
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, login)
	var state string
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			state = c.Value
		}
	}

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

	login := httptest.NewRequest(http.MethodGet, "/?rd=/admin/", nil)
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, login)
	var state string
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			state = c.Value
		}
	}

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

func TestOAuthCallbackBootstrapAdmin(t *testing.T) {
	d := &discordMock{member: &discord.Member{Roles: []string{"boot-role"}}}
	srv, _ := newTestServer(t, d, mapping.NewMemoryStore())

	login := httptest.NewRequest(http.MethodGet, "/", nil)
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, login)
	var state string
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "discord_auth_csrf" {
			state = c.Value
		}
	}

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

func TestAdminMappingsAuthz(t *testing.T) {
	maps := mapping.NewMemoryStore()
	srv, store := newTestServer(t, &discordMock{}, maps)

	viewer, _ := store.Create(context.Background(), "v1", []string{"viewer"}, time.Hour)
	admin, _ := store.Create(context.Background(), "a1", []string{"admin"}, time.Hour)

	// Non-admin forbidden
	req := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: viewer.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d", rr.Code)
	}

	// Admin can upsert + list
	body := `{"role_id":"r1","group_name":"operator"}`
	req = httptest.NewRequest(http.MethodPost, "/api/mappings", strings.NewReader(body))
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

	req = httptest.NewRequest(http.MethodDelete, "/api/mappings?role_id=r1&group_name=operator", nil)
	req.AddCookie(&http.Cookie{Name: "discord_auth_session", Value: admin.ID})
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
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
