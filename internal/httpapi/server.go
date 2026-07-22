package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yitech/discord-forward-auth/internal/audit"
	"github.com/yitech/discord-forward-auth/internal/authz"
	"github.com/yitech/discord-forward-auth/internal/config"
	"github.com/yitech/discord-forward-auth/internal/discord"
	"github.com/yitech/discord-forward-auth/internal/mapping"
	"github.com/yitech/discord-forward-auth/internal/session"
)

const (
	auditDefaultLimit = 25
	auditMaxLimit     = 100
)

type Server struct {
	cfg      *config.Config
	sessions session.Store
	mappings mapping.Store
	audit    audit.Store
	discord  discord.API
	authz    *authz.Resolver
	adminFS  fs.FS
	log      *slog.Logger
	now      func() time.Time
}

func New(
	cfg *config.Config,
	sessions session.Store,
	mappings mapping.Store,
	auditStore audit.Store,
	discordAPI discord.API,
	adminFS fs.FS,
	log *slog.Logger,
) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		sessions: sessions,
		mappings: mappings,
		audit:    auditStore,
		discord:  discordAPI,
		authz: &authz.Resolver{
			Mappings:           mappings,
			GuildID:            cfg.DiscordGuildID,
			BootstrapAdminRole: cfg.BootstrapAdminRole,
			AdminGroup:         cfg.AdminGroup,
		},
		adminFS: adminFS,
		log:     log,
		now:     time.Now,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_oauth", s.handleOAuthCallback)
	mux.HandleFunc("GET /_oauth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("GET /api/mappings", s.requireAdmin(s.handleListMappings))
	mux.HandleFunc("POST /api/mappings", s.requireAdmin(s.requireSameOrigin(s.handleUpsertMapping)))
	mux.HandleFunc("DELETE /api/mappings", s.requireAdmin(s.requireSameOrigin(s.handleDeleteMapping)))
	mux.HandleFunc("POST /api/sessions/revoke", s.requireAdmin(s.requireSameOrigin(s.handleRevokeSessions)))
	mux.HandleFunc("GET /api/audit", s.requireAdmin(s.handleListAudit))

	if s.adminFS != nil {
		mux.Handle("GET /admin/", s.adminHandler())
		mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusFound)
		})
	}

	mux.HandleFunc("/", s.handleForwardAuth)
	return mux
}

func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	id := s.sessionIDFromRequest(r)
	if id == "" {
		s.unauthenticated(w, r)
		return
	}

	sess, err := s.sessions.GetValid(r.Context(), id)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			s.clearSessionCookie(w)
			s.unauthenticated(w, r)
			return
		}
		s.log.Error("session lookup failed", "err", err)
		http.Error(w, "auth unavailable", http.StatusServiceUnavailable)
		return
	}

	if len(sess.Groups) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Best-effort last_seen update; ignore errors.
	_ = s.sessions.Touch(r.Context(), sess.ID)

	w.Header().Set(s.cfg.HeaderUser, sess.DiscordUser)
	w.Header().Set(s.cfg.HeaderGroups, strings.Join(sess.Groups, ","))
	w.WriteHeader(http.StatusOK)
}

// unauthenticated starts OAuth only for top-level navigations. Sub-resource
// ForwardAuth requests (CSS/JS/images/favicon) get a bare 401 so they cannot
// clobber the single CSRF cookie slot used by the document's login redirect.
func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if !isLoginNavigation(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.redirectToLogin(w, r)
}

func isLoginNavigation(r *http.Request) bool {
	mode := r.Header.Get("Sec-Fetch-Mode")
	dest := r.Header.Get("Sec-Fetch-Dest")
	if mode != "" || dest != "" {
		return mode == "navigate" || dest == "document"
	}
	// Clients without Fetch Metadata (curl, older browsers): treat HTML-ish
	// Accept (or empty) as a navigation; otherwise refuse like a sub-resource.
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || accept == "*/*"
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnPath, returnHost := originalReturn(r, s.cfg)
	state, err := encodeState(returnPath, returnHost)
	if err != nil {
		s.log.Error("encode state failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCSRFCookie(w, state)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.cfg.DiscordClientID)
	q.Set("redirect_uri", s.cfg.RedirectURI())
	q.Set("scope", "identify guilds.members.read")
	q.Set("state", state)

	http.Redirect(w, r, s.cfg.AuthorizeURL()+"?"+q.Encode(), http.StatusFound)
}

func originalReturn(r *http.Request, cfg *config.Config) (path, host string) {
	// Explicit return target (admin UI login).
	if rd := r.URL.Query().Get("rd"); rd != "" {
		return SafeReturnPath(rd), ""
	}
	// Traefik ForwardAuth provides original URI/host.
	if uri := r.Header.Get("X-Forwarded-Uri"); uri != "" {
		path = SafeReturnPath(uri)
	} else if r.URL.Path != "" && r.URL.Path != "/" {
		path = SafeReturnPath(r.URL.RequestURI())
	} else {
		// Direct browse to AUTH_HOST root. "/" is the bodyless ForwardAuth
		// endpoint; send humans to the admin UI after login instead.
		path = "/admin/"
	}

	host = config.NormalizeHost(r.Header.Get("X-Forwarded-Host"))
	if host != "" && !cfg.HostAllowed(host) {
		host = ""
	}
	return path, host
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		http.Error(w, "oauth error: "+errParam, http.StatusForbidden)
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	csrf, err := r.Cookie(s.cfg.CSRFCookieName)
	if err != nil || csrf.Value == "" {
		// Cookie already cleared after a prior callback (e.g. failed token
		// exchange) or never set — distinct from a state mismatch so operators
		// do not chase COOKIE_DOMAIN when the real fault was a consumed login.
		s.log.Warn("oauth callback missing csrf cookie")
		http.Error(w, "login session expired or already used; start login again", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(csrf.Value), []byte(state)) != 1 {
		s.log.Warn("oauth callback state mismatch")
		http.Error(w, "invalid state", http.StatusForbidden)
		return
	}
	s.clearCSRFCookie(w)

	st, err := decodeState(state, s.cfg)
	if err != nil {
		s.log.Warn("oauth callback invalid state payload", "err", err)
		http.Error(w, "invalid state", http.StatusForbidden)
		return
	}

	ctx := r.Context()
	tok, err := s.discord.ExchangeCode(ctx, code)
	if err != nil {
		s.log.Error("token exchange failed", "err", err)
		http.Error(w, "authentication failed; start login again", http.StatusForbidden)
		return
	}

	user, err := s.discord.GetMe(ctx, tok.AccessToken)
	if err != nil {
		s.log.Error("get me failed", "err", err)
		http.Error(w, "authentication failed", http.StatusForbidden)
		return
	}

	member, err := s.discord.GetGuildMember(ctx, tok.AccessToken, s.cfg.DiscordGuildID)
	// Access token intentionally discarded after this point.
	tok = nil
	if errors.Is(err, discord.ErrNotGuildMember) {
		http.Error(w, "not a guild member", http.StatusForbidden)
		return
	}
	if err != nil {
		s.log.Error("guild member lookup failed", "err", err)
		http.Error(w, "authentication failed", http.StatusForbidden)
		return
	}

	groups, err := s.authz.GroupsForRoles(ctx, member.Roles)
	if err != nil {
		s.log.Error("role mapping failed", "err", err)
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(groups) == 0 {
		http.Error(w, "no authorized groups", http.StatusForbidden)
		return
	}

	sess, err := s.sessions.Create(ctx, user.ID, groups, s.cfg.SessionTTL)
	if err != nil {
		s.log.Error("create session failed", "err", err)
		http.Error(w, "authentication failed", http.StatusServiceUnavailable)
		return
	}

	s.setSessionCookie(w, sess.ID, sess.ExpiresAt)
	http.Redirect(w, r, ReturnURL(st.Return, st.Host, s.cfg.AuthHost), http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if id := s.sessionIDFromRequest(r); id != "" {
		_ = s.sessions.Revoke(r.Context(), id)
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("logged out"))
}

func (s *Server) currentSession(ctx context.Context, r *http.Request) (*session.Session, error) {
	id := s.sessionIDFromRequest(r)
	if id == "" {
		return nil, session.ErrNotFound
	}
	return s.sessions.GetValid(ctx, id)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r.Context(), r)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "auth unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"discord_user": sess.DiscordUser,
		"groups":       sess.Groups,
		"admin":        authz.HasGroup(sess.Groups, s.cfg.AdminGroup),
		"guild_id":     s.cfg.DiscordGuildID,
		"admin_group":  s.cfg.AdminGroup,
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.currentSession(r.Context(), r)
		if err != nil {
			if errors.Is(err, session.ErrNotFound) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "auth unavailable", http.StatusServiceUnavailable)
			return
		}
		if !authz.HasGroup(sess.Groups, s.cfg.AdminGroup) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, sess)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedMutationOrigin(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) allowedMutationOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		switch site {
		case "same-origin":
			return true
		case "cross-site", "same-site":
			return false
		}
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return config.NormalizeHost(u.Host) == config.NormalizeHost(s.cfg.AuthHost)
}

type sessionKey struct{}

func sessionFromCtx(ctx context.Context) *session.Session {
	s, _ := ctx.Value(sessionKey{}).(*session.Session)
	return s
}

type mappingRequest struct {
	RoleID    string `json:"role_id"`
	GroupName string `json:"group_name"`
}

type revokeRequest struct {
	DiscordUser string `json:"discord_user"`
}

func (s *Server) handleListMappings(w http.ResponseWriter, r *http.Request) {
	list, err := s.mappings.List(r.Context(), s.cfg.DiscordGuildID)
	if err != nil {
		s.log.Error("list mappings failed", "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if list == nil {
		list = []mapping.Mapping{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleUpsertMapping(w http.ResponseWriter, r *http.Request) {
	var req mappingRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	req.GroupName = strings.TrimSpace(req.GroupName)
	if req.RoleID == "" || req.GroupName == "" {
		http.Error(w, "role_id and group_name required", http.StatusBadRequest)
		return
	}

	sess := sessionFromCtx(r.Context())
	updatedBy := ""
	if sess != nil {
		updatedBy = sess.DiscordUser
	}
	if err := s.mappings.Upsert(r.Context(), s.cfg.DiscordGuildID, req.RoleID, req.GroupName, updatedBy); err != nil {
		s.log.Error("upsert mapping failed", "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r.Context(), updatedBy, audit.ActionMappingUpsert, req.RoleID, map[string]any{
		"guild_id":   s.cfg.DiscordGuildID,
		"role_id":    req.RoleID,
		"group_name": req.GroupName,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(r.URL.Query().Get("role_id"))
	groupName := strings.TrimSpace(r.URL.Query().Get("group_name"))
	if roleID == "" || groupName == "" {
		http.Error(w, "role_id and group_name required", http.StatusBadRequest)
		return
	}
	if err := s.mappings.Delete(r.Context(), s.cfg.DiscordGuildID, roleID, groupName); err != nil {
		s.log.Error("delete mapping failed", "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	actor := ""
	if sess := sessionFromCtx(r.Context()); sess != nil {
		actor = sess.DiscordUser
	}
	s.recordAudit(r.Context(), actor, audit.ActionMappingDelete, roleID, map[string]any{
		"guild_id":   s.cfg.DiscordGuildID,
		"role_id":    roleID,
		"group_name": groupName,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.DiscordUser = strings.TrimSpace(req.DiscordUser)
	if req.DiscordUser == "" {
		http.Error(w, "discord_user required", http.StatusBadRequest)
		return
	}

	actor := ""
	if sess := sessionFromCtx(r.Context()); sess != nil {
		actor = sess.DiscordUser
	}
	if err := s.sessions.RevokeUser(r.Context(), req.DiscordUser); err != nil {
		s.log.Error("revoke user sessions failed", "err", err, "target", req.DiscordUser, "by", actor)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.recordAudit(r.Context(), actor, audit.ActionSessionRevokeUser, req.DiscordUser, map[string]any{
		"discord_user": req.DiscordUser,
	})
	s.log.Info("revoked user sessions", "target", req.DiscordUser, "by", actor)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r, auditDefaultLimit, auditMaxLimit)
	items, total, err := s.audit.List(r.Context(), limit, offset)
	if err != nil {
		s.log.Error("list audit failed", "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if items == nil {
		items = []audit.Event{}
	}
	writeJSON(w, http.StatusOK, audit.Page{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (s *Server) recordAudit(ctx context.Context, actor, action, target string, details map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Append(ctx, actor, action, target, details); err != nil {
		s.log.Error("audit append failed", "err", err, "action", action, "actor", actor, "target", target)
	}
}

func parsePagination(r *http.Request, defaultLimit, maxLimit int) (limit, offset int) {
	limit = defaultLimit
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (s *Server) adminHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.adminFS))
	return http.StripPrefix("/admin/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(s.adminFS, path); err != nil {
			http.ServeFileFS(w, r, s.adminFS, "index.html")
			return
		}
		fileServer.ServeHTTP(w, r)
	}))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	return dec.Decode(dest)
}
