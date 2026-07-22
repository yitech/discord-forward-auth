package audit

import (
	"context"
	"encoding/json"
	"time"
)

const (
	ActionMappingUpsert     = "mapping.upsert"
	ActionMappingDelete     = "mapping.delete"
	ActionSessionRevokeUser = "session.revoke_user"
)

type Event struct {
	ID      int64           `json:"id"`
	At      time.Time       `json:"at"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Details json.RawMessage `json:"details"`
}

type Page struct {
	Items  []Event `json:"items"`
	Total  int64   `json:"total"`
	Limit  int     `json:"limit"`
	Offset int     `json:"offset"`
}

type Store interface {
	Append(ctx context.Context, actor, action, target string, details map[string]any) error
	List(ctx context.Context, limit, offset int) ([]Event, int64, error)
}
