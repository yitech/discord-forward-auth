# Discord setup

Most deploy failures for this service are Discord-side configuration, not Traefik or env wiring. Work through this section in order before debugging ForwardAuth.

## No bot required

The service authenticates entirely with the **user’s** OAuth token via Discord’s

`GET /users/@me/guilds/{guild.id}/member`

(scope `guilds.members.read`). You do **not** need:

- a bot token
- a bot invited to the guild
- the privileged `GUILD_MEMBERS` intent

There is no `DISCORD_BOT_TOKEN` in `.env.example` on purpose — that is a design choice, not an omission.

## Walkthrough

### 1. Enable Developer Mode

**User Settings → Advanced → Developer Mode**: on.

You need this to copy guild, role, and user IDs. Nothing below works without it.

### 2. Create the Discord application

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) → **New Application**.
2. Under **OAuth2**, copy:
   - **Client ID** → `DISCORD_CLIENT_ID`
   - **Client Secret** → `DISCORD_CLIENT_SECRET`

### 3. Register the redirect URI

In **OAuth2 → Redirects**, add exactly:

```text
https://<AUTH_HOST>/_oauth
```

Example: `https://auth.example.com/_oauth`

Then click **Save Changes**.

Discord matches this as an **exact string**:

- `/_oauth/` (trailing slash) is a different URI and will fail.
- Note the leading underscore — it is intentional.
- Scheme and host must match what Traefik presents publicly (`https`, no wrong hostname).

Failure mode is Discord’s own **Invalid OAuth2 redirect_uri** page. The request never reaches this service, so there is nothing useful in the app logs.

### 4. Leave “Requires OAuth2 Code Grant” off

Under the OAuth2 settings for the application, confirm **Requires OAuth2 Code Grant** is **OFF**. This service uses the standard authorization-code redirect flow.

Scopes requested at login: `identify`, `guilds.members.read`.

### 5. Copy the guild ID

Right-click the server icon → **Copy Server ID** → `DISCORD_GUILD_ID`.

Only members of this guild can authenticate.

### 6. Create a normal role for bootstrap admin

1. In **Server Settings → Roles**, create a **new role** you control (for example `Auth Admin`).
2. Assign that role to yourself (and any other first admins).
3. Right-click the role → **Copy Role ID** → `BOOTSTRAP_ADMIN_ROLE_ID`.

That role always maps to the admin group (break-glass / first admin). See the traps below — most “no authorized groups” failures start here.

## Common traps

### Bot-managed roles cannot be the bootstrap role

Discord auto-creates a `managed` integration role for every bot in a guild, named after the bot. In the roles list and the role picker they look ordinary, but they **cannot be assigned to a human**.

Setting `BOOTSTRAP_ADMIN_ROLE_ID` to a managed role yields `no authorized groups` forever: the ID is valid and the role exists, but it never appears in any human’s `member.roles`.

Integration role names also change when the bot is renamed, so name-based identification is actively misleading.

**Rule:** `BOOTSTRAP_ADMIN_ROLE_ID` must be a role you created yourself. Bot integration roles (`managed: true`) will always resolve to zero groups. If you can call `GET /guilds/{guild.id}/roles`, confirm `managed == false` for the role you copy.

### Guild owners have no roles by default

Discord’s `member.roles` **excludes `@everyone`**, and guild owners hold permissions implicitly rather than through a role. The guild owner — usually the person setting this up — often gets `roles: []` and `no authorized groups` despite full Discord authority.

Being owner is not enough. The bootstrap role must be **explicitly assigned** to your account.

### Role names are not unique

The service matches role **IDs**, not names. Discord allows several roles with the same name, and the role picker does not distinguish them. Always copy the Role ID; do not trust the display name.

## Troubleshooting

| Response | Stage | Likely cause |
|---|---|---|
| Discord’s `Invalid OAuth2 redirect_uri` page | before the service | Redirect URI not registered, or trailing-slash / scheme / host mismatch |
| `missing code or state` (400) | callback | `/_oauth` opened directly rather than via Discord |
| `login session expired or already used; start login again` (403) | callback | CSRF cookie gone: >10 min elapsed, or a consumed callback was reloaded |
| `invalid state` (403) | callback | State/cookie mismatch — check `COOKIE_DOMAIN` is the shared parent domain |
| `authentication failed; start login again` (403) | token exchange | Transient Discord failure; the server log carries Discord’s actual error |
| `not a guild member` (403) | guild lookup | User is not in `DISCORD_GUILD_ID` |
| `no authorized groups` (403) | authorization | In the guild, but roles map to nothing — bootstrap role not held, or it is a `managed` bot role |
| `forbidden` (403) from ForwardAuth | session check | Session exists but carries zero groups |
| `unauthorized` (401) | ForwardAuth | Sub-resource request without a session — expected, not an error |

After Discord setup, return to the [README](../README.md) for `COOKIE_DOMAIN`, Traefik, and Compose.
