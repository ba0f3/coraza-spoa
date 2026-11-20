//go:build integration

package autoban

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRedisConnection talks to a real Redis primary. A missing or unreachable
// fixture is a hard failure: never skip a real-store assertion.
func TestRedisConnection(t *testing.T) {
	addr := os.Getenv("AUTOBAN_REDIS_ADDR")
	if addr == "" {
		t.Fatal("AUTOBAN_REDIS_ADDR is required for integration tests")
	}
	cfg := testRedisConfig()
	cfg.Addresses = []string{addr}
	store, err := NewRedisStore(cfg)
	if err != nil {
		t.Fatalf("building store: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	now, err := store.client.Time(ctx).Result()
	if err != nil {
		t.Fatalf("real Redis TIME failed: %v", err)
	}
	if now.IsZero() {
		t.Fatal("Redis TIME returned zero time")
	}

	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := store.eval(canceled, "return 1", nil, nil, false); err == nil {
		t.Fatal("bounded cancellation must fail")
	}
}
