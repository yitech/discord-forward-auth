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

- Server-side opaque sessions in Postgres (revocable on logout).
- Role→group mappings edited in the admin UI at `https://<AUTH_HOST>/admin/`.
- `BOOTSTRAP_ADMIN_ROLE_ID` always grants the admin group (break-glass / first admin).

## Quick start (Docker Compose)

1. Create a Discord application OAuth2 redirect: `https://<AUTH_HOST>/_oauth`
   - Scopes: `identify`, `guilds.members.read`
2. Copy `.env.example` → `.env` and fill Discord + guild + bootstrap role IDs.
3. Run:

```bash
cd deploy
docker compose --env-file ../.env up --build
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
| `SESSION_TTL` | `1800` | Session lifetime (seconds) |
| `MAPPING_CACHE_TTL` | `30` | Role→group cache (seconds; `0` = no cache) |
| `ADMIN_GROUP` | `admin` | Group required for admin UI/API |
| `COOKIE_NAME` | `__Host-discord_auth_session` | Session cookie name |
| `COOKIE_DOMAIN` | _(empty)_ | Set for shared subdomain cookies (e.g. `.example.com`) |
| `HEADER_USER` | `X-Auth-User` | Identity header name |
| `HEADER_GROUPS` | `X-Auth-Groups` | Groups header name |
| `LISTEN_ADDR` | `:4181` | HTTP listen address |

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

## Local development

```bash
# Postgres
docker compose -f deploy/docker-compose.yml up postgres -d

# Backend
export $(grep -v '^#' .env | xargs)
go run ./cmd/discord-auth

# Admin UI (proxies /api to :4181)
cd web && npm install && npm run dev
```

Production UI is embedded: `cd web && npm run build` writes into `cmd/discord-auth/admin/`.

## Auth flow (summary)

1. Unauthenticated ForwardAuth → `302` to Discord authorize (`state` + CSRF cookie).
2. Callback `/_oauth` exchanges code, loads guild member roles, maps to groups.
3. Empty groups or non-member → `403`. Discord/DB errors → fail-closed.
4. Session cookie set; Discord access token discarded.
5. Authenticated → `200` + `X-Auth-*` headers.

## License

See repository license (if present).
