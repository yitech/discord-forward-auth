CREATE TABLE IF NOT EXISTS host_group_policies (
    host            TEXT PRIMARY KEY,
    required_groups TEXT[] NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT,
    CONSTRAINT host_group_policies_groups_nonempty CHECK (cardinality(required_groups) > 0)
);
