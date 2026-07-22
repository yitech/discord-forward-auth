# discord-forward-auth

Independent, reusable [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) service. Any Traefik-protected app can require Discord login with guild membership and role→group authorization—without changing the app itself.

Downstream apps receive identity via headers:

| Header | Value |
|---|---|
| `X-Auth-User` | Discord user snowflake |
| `X-Auth-Groups` | Comma-separated groups (e.g. `admin,operator`) |

Header names are configurable (`HEADER_USER`, `HEADER_GROUPS`).

## Architecture

```
Browser ──HTTPS──> Traefik ──ForwardAuth──> discord-auth
                     │                            ├─> Discord OAuth2 / API
                     │  200 + X-Auth-* headers    └─> Postgres (sessions + mappings)
                     ▼
                 Protected app
```

- Server-side opaque sessions in Postgres (revocable on logout or admin kick).
- Role→group mappings edited in the admin UI at `https://<AUTH_HOST>/admin/`.
- `BOOTSTRAP_ADMIN_ROLE_ID` always grants the admin group (break-glass / first admin).

## Multi-host cookies (required)

The documented topology is `auth.example.com` (OAuth callback + admin) plus apps like `app.example.com`.

**You must set `COOKIE_DOMAIN` to the shared parent domain** (e.g. `.example.com`). Without it:

1. The CSRF cookie is scoped to the app host during ForwardAuth, so the callback on `AUTH_HOST` fails with `403 invalid state`.
2. The session cookie set on `AUTH_HOST` is never sent to the app host → login loop.

Startup **fails** if `COOKIE_DOMAIN` is empty, unless you explicitly set `SINGLE_HOST=true` (only when `AUTH_HOST` itself is the sole protected host).

## Container image (GHCR)

CI builds and publishes multi-arch (`linux/amd64`, `linux/arm64`) images to GitHub Container Registry on every push to `main` and on version tags (`v*`).

```bash
docker pull ghcr.io/yitech/discord-forward-auth:latest
# or a release tag / commit sha:
# docker pull ghcr.io/yitech/discord-forward-auth:1.0.0
# docker pull ghcr.io/yitech/discord-forward-auth:sha-<gitsha>
```

If the package is private, authenticate first:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

## Quick start (Docker Compose)

1. Create a Discord application OAuth2 redirect: `https://<AUTH_HOST>/_oauth`
   - Scopes: `identify`, `guilds.members.read`
2. Copy `.env.example` → `.env` and fill Discord + guild + bootstrap role IDs.
3. Set `COOKIE_DOMAIN=.example.com` (matching your real parent domain).
4. Run (build locally, or pull from GHCR):

```bash
cd deploy
# Local build:
docker compose --env-file ../.env up --build

# Or use the published image:
IMAGE=ghcr.io/yitech/discord-forward-auth:latest docker compose --env-file ../.env up
```

Service listens on `:4181`. Admin UI: `https://<AUTH_HOST>/admin/` (behind Traefik TLS).

## Configuration

| Env | Default | Description |
|---|---|---|
| `AUTH_HOST` | required | Public hostname for OAuth callback |
| `DISCORD_CLIENT_ID` | required | Discord OAuth client ID |
| `DISCORD_CLIENT_SECRET` | required | Discord OAuth client secret |
| `DISCORD_GUILD_ID` | required | Allowed Discord guild |
| `BOOTSTRAP_ADMIN_ROLE_ID` | required | Discord role that always maps to admin |
| `DATABASE_URL` | required | Postgres connection string |
| `COOKIE_DOMAIN` | required\* | Shared parent domain (e.g. `.example.com`) for multi-host |
| `SINGLE_HOST` | `false` | Opt into host-only cookies when only `AUTH_HOST` is protected |
| `SESSION_TTL` | `1800` | Session lifetime (seconds) |
| `MAPPING_CACHE_TTL` | `30` | Role→group cache (seconds; `0` = no cache) |
| `ADMIN_GROUP` | `admin` | Group required for admin UI/API |
| `COOKIE_NAME` | `__Host-discord_auth_session` | Session cookie name (`__Secure-` when domain set) |
| `HEADER_USER` | `X-Auth-User` | Identity header name |
| `HEADER_GROUPS` | `X-Auth-Groups` | Groups header name |
| `LISTEN_ADDR` | `:4181` | HTTP listen address |

\*Required unless `SINGLE_HOST=true`.

## Traefik

See [deploy/traefik.example.yml](deploy/traefik.example.yml).

**Strip client `X-Auth-*` headers** at the edge before ForwardAuth. ForwardAuth only *adds* `authResponseHeaders`; forged client headers must be removed first.

```yaml
middlewares:
  strip-auth-headers:
    headers:
      customRequestHeaders:
        X-Auth-User: ""
        X-Auth-Groups: ""
  discord-auth:
    forwardAuth:
      address: http://discord-auth:4181
      authResponseHeaders:
        - X-Auth-User
        - X-Auth-Groups
```

## Admin API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/me` | Current session |
| `GET/POST/DELETE` | `/api/mappings` | Role→group CRUD (admin) |
| `POST` | `/api/sessions/revoke` | Body `{"discord_user":"<id>"}` — revoke all sessions for a user (admin) |

State-changing admin routes also require same-origin (`Origin` / `Sec-Fetch-Site`).

## Local development

```bash
# Postgres
docker compose -f deploy/docker-compose.yml up postgres -d

# Backend (SINGLE_HOST=true is fine for local auth-host-only testing)
export $(grep -v '^#' .env | xargs)
go run ./cmd/discord-auth

# Admin UI (proxies /api to :4181)
cd web && npm install && npm run dev
```

Production UI is embedded: `cd web && npm run build` writes into `cmd/discord-auth/admin/`.

## Auth flow (summary)

1. Unauthenticated **top-level** ForwardAuth (`Sec-Fetch-Mode: navigate` / `Sec-Fetch-Dest: document`, or HTML `Accept`) → `302` to Discord authorize (`state` + CSRF cookie). Sub-resource requests get bare `401` so they cannot clobber the CSRF cookie.
2. Callback `/_oauth` exchanges code (one transport retry; 15s client timeout), loads guild member roles, maps to groups.
3. Empty groups or non-member → `403`. Discord/DB errors → fail-closed. A missing CSRF cookie (consumed/expired login) returns a distinct message from state mismatch.
4. Session cookie set; Discord access token discarded.
5. Redirect back to the original app host/path (host must be under `COOKIE_DOMAIN` or equal `AUTH_HOST`).
6. Authenticated → `200` + `X-Auth-*` headers.

## License

See repository license (if present).
