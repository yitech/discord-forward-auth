# discord-forward-auth

Independent, reusable [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) service. Any Traefik-protected app can require Discord login with guild membership, role→group mapping, and per-hostname group ACLs—without changing the app itself.

Downstream apps receive identity via headers:

| Header | Value |
|---|---|
| `X-Auth-User` | Discord user snowflake |
| `X-Auth-Groups` | Comma-separated groups (e.g. `admin,engineer`) |

Header names are configurable (`HEADER_USER`, `HEADER_GROUPS`).

## Architecture

```
Browser ──HTTPS──> Traefik ──ForwardAuth──> discord-auth
                     │                            ├─> Discord OAuth2 / API
                     │  200 + X-Auth-* headers    └─> Postgres (sessions + mappings + host policies)
                     ▼
                 Protected app
```

- Server-side opaque sessions in Postgres (revocable on logout or admin kick).
- Role→group mappings and host→group policies edited in the admin UI at `https://<AUTH_HOST>/admin/`.
- Admin mutations write an append-only audit history (paginated in the UI / `/api/audit`).
- `BOOTSTRAP_ADMIN_ROLE_ID` always grants the admin group (break-glass / first admin).

## Host → group ACL

After login, ForwardAuth checks `X-Forwarded-Host` against admin-configured host policies:

1. **Discord role → group** (existing): e.g. Discord “Engineer” → `engineer`, “BD” → `bd`
2. **Hostname → required group(s)** (new): e.g. `grafana.example.com` → `engineer`, `metabase.example.com` → `bd`

Rules:

- User needs **any one** of the host’s required groups.
- Hosts with **no policy** are **denied** (fail-closed) so a new Traefik app is not open to every logged-in guild member.
- Empty/`AUTH_HOST` skips host ACL (direct auth-host traffic).
- The `admin` group (`ADMIN_GROUP`) **bypasses** host ACL.

Example admin policies:

| Host | Required groups |
|---|---|
| `grafana.example.com` | `engineer` |
| `metabase.example.com` | `bd` |
| `wiki.example.com` | `engineer`, `bd` |

Host-policy edits apply on the next ForwardAuth request. Role→group mapping changes still require re-login or session revoke (groups are snapshotted at login).

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

## Discord setup

Before Compose/Traefik, configure the Discord application, guild, and bootstrap role.

See **[docs/discord-setup.md](docs/discord-setup.md)** for the full walkthrough, common traps (no bot required, managed bot roles, guild-owner empty roles), and an error→cause troubleshooting table.

## Quick start (Docker Compose)

1. Complete [Discord setup](docs/discord-setup.md) (redirect `https://<AUTH_HOST>/_oauth`, guild ID, self-assigned bootstrap role).
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
| `BOOTSTRAP_ADMIN_ROLE_ID` | required | Normal (non-managed) Discord role that always maps to admin; must be assigned to the user |
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
| `GET/POST/DELETE` | `/api/host-policies` | Host→group ACL CRUD (admin). POST body: `{"host":"grafana.example.com","required_groups":["engineer"]}`. DELETE query: `?host=` |
| `POST` | `/api/sessions/revoke` | Body `{"discord_user":"<id>"}` — revoke all sessions for a user (admin) |
| `GET` | `/api/audit` | Paginated audit history (admin). Query: `limit` (default 25, max 100), `offset` (default 0) |

State-changing admin routes also require same-origin (`Origin` / `Sec-Fetch-Site`).

Audit events are recorded for:

- `login.success` / `login.denied` — Discord user id, username, client IP (`X-Forwarded-For` / `X-Real-IP` / remote addr), groups or deny reason, return host/path
- `session.logout` — user + IP
- mapping upsert/delete, host-policy upsert/delete, session revoke

Response shape:

```json
{
  "items": [{"id": 1, "at": "...", "actor": "...", "action": "login.success", "target": "...", "details": {"ip": "...", "username": "...", "groups": ["admin"]}}],
  "total": 42,
  "limit": 25,
  "offset": 0
}
```

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
6. Authenticated → host ACL check on `X-Forwarded-Host` → `200` + `X-Auth-*` headers, or `403` if the host has no policy / user lacks a required group (admins bypass).

## License

See repository license (if present).
