package audit_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/yitech/discord-forward-auth/internal/audit"
)

func TestMemoryStoreListPagination(t *testing.T) {
	s := audit.NewMemoryStore()
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		if err := s.Append(ctx, "actor", audit.ActionMappingUpsert, "r"+strconv.Itoa(i), map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}

	items, total, err := s.List(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("total=%d", total)
	}
	if len(items) != 2 {
		t.Fatalf("len=%d", len(items))
	}
	if items[0].ID != 5 || items[1].ID != 4 {
		t.Fatalf("order=%v,%v", items[0].ID, items[1].ID)
	}

	items, total, err = s.List(ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(items) != 2 || items[0].ID != 3 || items[1].ID != 2 {
		t.Fatalf("page2 items=%v total=%d", items, total)
	}

	items, total, err = s.List(ctx, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(items) != 1 || items[0].ID != 1 {
		t.Fatalf("page3 items=%v total=%d", items, total)
	}

	items, _, err = s.List(ctx, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected empty, got %v", items)
	}
}
