CREATE TABLE IF NOT EXISTS auth_sessions (
    id            TEXT PRIMARY KEY,
    discord_user  TEXT NOT NULL,
    groups        TEXT[] NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked       BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS auth_sessions_discord_user_idx ON auth_sessions (discord_user);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx ON auth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS role_group_mappings (
    guild_id    TEXT NOT NULL,
    role_id     TEXT NOT NULL,
    group_name  TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT,
    PRIMARY KEY (guild_id, role_id, group_name)
);
