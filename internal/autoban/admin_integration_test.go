//go:build integration

package autoban

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"
)

func envRedisAddr() string {
	addr := os.Getenv("AUTOBAN_REDIS_ADDR")
	if addr == "" {
		panic("AUTOBAN_REDIS_ADDR is required for integration tests")
	}
	return addr
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func TestAdminIntegration(t *testing.T) {
	addr := envRedisAddr()
	cfg := testRedisConfig()
	cfg.Addresses = []string{addr}
	cfg.KeyPrefix = "admin-it-" + randomHex(6)
	store, err := NewRedisStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	compiled, err := Compile(ConfigInput{Enabled: true, Redis: testRedisConfig()})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHandler(store, func() Config { return compiled })

	body, _ := json.Marshal(map[string]string{
		"mode": "enforce", "scope": "application", "application": "app1",
		"ip": "203.0.113.10", "operation_id": "admin-op",
		"suppress_for": "60s", "reason": "operator",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/bans/unban", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban status = %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Nonce == "" {
		t.Fatalf("unban result = %s (%v)", rec.Body.String(), err)
	}

	// Replaying the same operation returns the same nonce.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/v1/bans/unban", bytes.NewReader(body)))
	var replay struct {
		Replayed bool   `json:"replayed"`
		Nonce    string `json:"nonce"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &replay); err != nil || !replay.Replayed || replay.Nonce != result.Nonce {
		t.Fatalf("replay result = %s (%v)", rec2.Body.String(), err)
	}

	// Inspection reports both scopes without an error.
	inspect := httptest.NewRecorder()
	handler.ServeHTTP(inspect, httptest.NewRequest(http.MethodGet,
		"/v1/bans/inspect?mode=enforce&application=app1&ip=203.0.113.10", nil))
	if inspect.Code != http.StatusOK {
		t.Fatalf("inspect status = %d", inspect.Code)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = store.Inspect(ctx, InspectRequest{Subject: Subject{
		Application: "app1", IP: netip.MustParseAddr("203.0.113.10"), Mode: ModeEnforce,
	}})
	if err != nil {
		t.Fatal(err)
	}
}
