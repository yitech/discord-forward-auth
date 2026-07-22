package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yitech/discord-forward-auth/internal/session"
)

func TestMemoryStoreExpiryAndRevoke(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	sess, err := store.Create(ctx, "u1", []string{"g"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetValid(ctx, sess.ID)
	if err != nil || got.DiscordUser != "u1" {
		t.Fatalf("got=%v err=%v", got, err)
	}

	if err := store.Revoke(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetValid(ctx, sess.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestNewID(t *testing.T) {
	a, err := session.NewID()
	if err != nil || a == "" {
		t.Fatal(err)
	}
	b, err := session.NewID()
	if err != nil || a == b {
		t.Fatal("expected unique ids")
	}
}
