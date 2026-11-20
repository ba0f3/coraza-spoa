package autoban

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type adminStore struct {
	inspectResult InspectResult
	listResult    ListResult
	unbanResult   UnbanResult
	unbanErr      error
	listErr       error
	lastUnban     UnbanRequest
}

func (s *adminStore) Begin(context.Context, BeginCommand) (BeginResult, error) {
	return BeginResult{}, nil
}
func (s *adminStore) Observe(context.Context, ObserveCommand) (ObserveResult, error) {
	return ObserveResult{}, nil
}
func (s *adminStore) Unban(_ context.Context, r UnbanRequest) (UnbanResult, error) {
	s.lastUnban = r
	return s.unbanResult, s.unbanErr
}
func (s *adminStore) Inspect(context.Context, InspectRequest) (InspectResult, error) {
	return s.inspectResult, nil
}
func (s *adminStore) List(context.Context, ListRequest) (ListResult, error) {
	return s.listResult, s.listErr
}

func enabledSnapshot() func() Config {
	cfg, _ := Compile(ConfigInput{Enabled: true, Redis: RedisConfig{
		Addresses: []string{"127.0.0.1:6379"}, KeyPrefix: "test",
	}})
	return func() Config { return cfg }
}

func TestAdminValidation(t *testing.T) {
	store := &adminStore{unbanResult: UnbanResult{
		StateExisted: true, Replayed: false, Nonce: "nonce",
		RemainingApplicationBansEvaluated: true, ResetAtMS: 1000, SuppressedUntilMS: 61000,
	}}
	handler := NewAdminHandler(store, enabledSnapshot())

	payload := func(mode, scope, app, ip, op, suppress, reason string) string {
		b, _ := json.Marshal(map[string]string{
			"mode": mode, "scope": scope, "application": app, "ip": ip,
			"operation_id": op, "suppress_for": suppress, "reason": reason,
		})
		return string(b)
	}
	cases := []struct {
		name, body string
		want       int
	}{
		{"valid", payload("enforce", "application", "app1", "203.0.113.10", "op1", "1m", "operator"), 200},
		{"bad mode", payload("bogus", "application", "app1", "203.0.113.10", "op1", "1m", "operator"), 400},
		{"bad scope", payload("enforce", "bogus", "app1", "203.0.113.10", "op1", "1m", "operator"), 400},
		{"bad ip", payload("enforce", "application", "app1", "not-ip", "op1", "1m", "operator"), 400},
		{"bad op id", payload("enforce", "application", "app1", "203.0.113.10", "bad/id", "1m", "operator"), 400},
		{"empty reason", payload("enforce", "application", "app1", "203.0.113.10", "op1", "1m", " "), 400},
		{"suppression above", payload("enforce", "application", "app1", "203.0.113.10", "op1", "25h", "operator"), 400},
		{"malformed json", "{", 400},
		{"oversized body", strings.Repeat("x", 8193), 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/bans/unban", bytes.NewBufferString(tc.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	store.unbanErr = ErrOperationConflict
	req := httptest.NewRequest(http.MethodPost, "/v1/bans/unban", strings.NewReader(payload("enforce", "application", "app1", "203.0.113.10", "op1", "1m", "operator")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d", rec.Code)
	}

	store.unbanErr = &StoreError{Reason: ReasonConnection}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/bans/unban", strings.NewReader(payload("enforce", "application", "app1", "203.0.113.10", "op1", "1m", "operator"))))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d", rec.Code)
	}

	// Global reset reports application bans unevaluated.
	store.unbanErr = nil
	store.unbanResult.RemainingApplicationBansEvaluated = false
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/bans/unban", strings.NewReader(payload("enforce", "global", "", "203.0.113.10", "op2", "1m", "operator"))))
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["remaining_application_bans_evaluated"] != false {
		t.Fatalf("global reset must report unevaluated: %v", out)
	}
}

func TestAdminSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.sock")
	server, listener, err := NewAdminSocket(path, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %o, want 600", info.Mode().Perm())
	}
	if _, ok := listener.Addr().(*net.UnixAddr); !ok {
		t.Fatal("admin listener must be a Unix socket")
	}

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewAdminSocket(regular, http.NotFoundHandler()); err == nil {
		t.Fatal("binding over a regular file must fail")
	}
	content, _ := os.ReadFile(regular)
	if string(content) != "keep" {
		t.Fatal("regular file must be left unchanged")
	}
}

func TestAdminPagination(t *testing.T) {
	store := &adminStore{listResult: ListResult{
		Bans: []BanRecord{}, Cursor: "42", Examined: 50,
	}}
	handler := NewAdminHandler(store, enabledSnapshot())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/bans?mode=enforce&scope=application&application=app1&limit=100", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["cursor"] == "" || out["examined"] != float64(50) {
		t.Fatalf("unexpected page: %v", out)
	}
	// Limit bounds.
	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/v1/bans?mode=enforce&scope=application&limit=101", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("limit above 100 must fail, got %d", bad.Code)
	}
}

func TestAdminCursorBounds(t *testing.T) {
	store := &adminStore{listResult: ListResult{Bans: []BanRecord{}, Cursor: "42", Examined: 1}}
	handler := NewAdminHandler(store, enabledSnapshot())
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/bans?mode=enforce&scope=application&application=app1&limit=10", nil))
	var page map[string]interface{}
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	cursor, _ := page["cursor"].(string)
	if cursor == "" {
		t.Fatal("expected a continuation cursor")
	}

	// Query mismatch is a 400.
	mismatch := httptest.NewRecorder()
	handler.ServeHTTP(mismatch, httptest.NewRequest(http.MethodGet, "/v1/bans?mode=enforce&scope=application&application=other&limit=10&cursor="+cursor, nil))
	if mismatch.Code != http.StatusBadRequest {
		t.Fatalf("mismatch status = %d", mismatch.Code)
	}
	// Unknown cursor is a 410.
	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/v1/bans?mode=enforce&scope=application&application=app1&limit=10&cursor=missing", nil))
	if unknown.Code != http.StatusGone {
		t.Fatalf("unknown cursor status = %d", unknown.Code)
	}

	// Cursor capacity is a 503.
	h := &adminHandler{store: store, snapshot: enabledSnapshot(), cursors: map[string]*cursorState{}}
	for i := 0; i < maxCursorCount; i++ {
		h.cursors[string(rune('a'+i))] = &cursorState{created: time.Now(), lastUsed: time.Now()}
	}
	full := httptest.NewRecorder()
	NewAdminHandler(store, enabledSnapshot())
	// exercise capacity through the concrete handler
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/bans", h.list)
	mux.ServeHTTP(full, httptest.NewRequest(http.MethodGet, "/v1/bans?mode=enforce&scope=application&limit=10", nil))
	if full.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d: %s", full.Code, full.Body.String())
	}
}
