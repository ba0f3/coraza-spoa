package autoban

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	maxAdminBody   = 8192
	maxCursorCount = 32
	maxPendingKeys = 1000
	cursorTTL      = 120 * time.Second
	adminDeadline  = 100 * time.Millisecond
)

type cursorState struct {
	redisCursor string
	query       string
	created     time.Time
	lastUsed    time.Time
}

type adminHandler struct {
	store    Store
	snapshot func() Config

	mu      sync.Mutex
	cursors map[string]*cursorState
}

// NewAdminHandler exposes bounded inspection and reset over an HTTP handler
// intended only for a Unix socket. It never treats admin input as request
// policy degradation.
func NewAdminHandler(store Store, snapshot func() Config) http.Handler {
	h := &adminHandler{store: store, snapshot: snapshot, cursors: map[string]*cursorState{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/bans/inspect", h.inspect)
	mux.HandleFunc("/v1/bans", h.list)
	mux.HandleFunc("/v1/bans/unban", h.unban)
	return mux
}

func (h *adminHandler) enabled(w http.ResponseWriter) bool {
	if h.snapshot == nil || !h.snapshot().Enabled() {
		http.Error(w, "autoban disabled", http.StatusNotFound)
		return false
	}
	return true
}

func parseMode(raw string) (Mode, error) {
	m := Mode(raw)
	if m != ModeObserve && m != ModeEnforce {
		return "", fmt.Errorf("invalid mode")
	}
	return m, nil
}

func parseScope(raw string) (Scope, error) {
	s := Scope(raw)
	if s != ScopeApplication && s != ScopeGlobal {
		return "", fmt.Errorf("invalid scope")
	}
	return s, nil
}

func parseIP(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

func (h *adminHandler) inspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !h.enabled(w) {
		return
	}
	mode, err := parseMode(r.URL.Query().Get("mode"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ip, err := parseIP(r.URL.Query().Get("ip"))
	if err != nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), adminDeadline)
	defer cancel()
	res, err := h.store.Inspect(ctx, InspectRequest{Subject: Subject{
		Application: r.URL.Query().Get("application"), IP: ip, Mode: mode,
	}})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bans": res.Bans, "suppressed_until_ms": res.SuppressedUntilMS,
	})
}

func (h *adminHandler) list(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !h.enabled(w) {
		return
	}
	q := r.URL.Query()
	mode, err := parseMode(q.Get("mode"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scope, err := parseScope(q.Get("scope"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit := 0
	if _, err := fmt.Sscan(q.Get("limit"), &limit); err != nil || limit < 1 || limit > 100 {
		http.Error(w, "invalid limit", http.StatusBadRequest)
		return
	}
	queryKey := fmt.Sprintf("%s|%s|%s|%s|%d", mode, scope, q.Get("application"), q.Get("cursor"), limit)
	request := ListRequest{Mode: mode, Scope: scope, Application: q.Get("application"), Limit: limit}

	h.mu.Lock()
	h.cleanupCursorsLocked(time.Now())
	if cursor := q.Get("cursor"); cursor != "" {
		state, ok := h.cursors[cursor]
		if !ok || time.Since(state.created) > cursorTTL {
			h.mu.Unlock()
			http.Error(w, "cursor expired", http.StatusGone)
			return
		}
		if state.query != queryKey {
			h.mu.Unlock()
			http.Error(w, "cursor query mismatch", http.StatusBadRequest)
			return
		}
		request.Cursor = state.redisCursor
		state.lastUsed = time.Now()
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), adminDeadline)
	defer cancel()
	res, err := h.store.List(ctx, request)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if res.Examined > maxPendingKeys {
		http.Error(w, "scan batch too large", http.StatusServiceUnavailable)
		return
	}

	nextCursor := ""
	if res.Cursor != "0" && res.Cursor != "" {
		nextCursor = randomAdminCursor()
		h.mu.Lock()
		h.cleanupCursorsLocked(time.Now())
		if len(h.cursors) >= maxCursorCount {
			h.mu.Unlock()
			http.Error(w, "cursor capacity", http.StatusServiceUnavailable)
			return
		}
		h.cursors[nextCursor] = &cursorState{
			redisCursor: res.Cursor, query: queryKey,
			created: time.Now(), lastUsed: time.Now(),
		}
		h.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bans": res.Bans, "cursor": nextCursor, "examined": res.Examined,
	})
}

func (h *adminHandler) cleanupCursorsLocked(now time.Time) {
	for id, state := range h.cursors {
		if now.Sub(state.created) > cursorTTL {
			delete(h.cursors, id)
		}
	}
}

func randomAdminCursor() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

type unbanRequest struct {
	Mode        string `json:"mode"`
	Scope       string `json:"scope"`
	Application string `json:"application"`
	IP          string `json:"ip"`
	OperationID string `json:"operation_id"`
	SuppressFor string `json:"suppress_for"`
	Reason      string `json:"reason"`
}

func (h *adminHandler) unban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !h.enabled(w) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBody+1))
	if err != nil || len(body) > maxAdminBody {
		http.Error(w, "body too large", http.StatusBadRequest)
		return
	}
	var input unbanRequest
	if err := json.Unmarshal(body, &input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	mode, err := parseMode(input.Mode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scope, err := parseScope(input.Scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ip, err := parseIP(input.IP)
	if err != nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	if !idPattern.MatchString(input.OperationID) || strings.TrimSpace(input.Reason) == "" {
		http.Error(w, "invalid operation_id or reason", http.StatusBadRequest)
		return
	}
	suppress := 60 * time.Second
	if input.SuppressFor != "" {
		d, err := time.ParseDuration(input.SuppressFor)
		if err != nil || d < 0 || d > 24*time.Hour {
			http.Error(w, "invalid suppress_for", http.StatusBadRequest)
			return
		}
		suppress = d
	}
	ctx, cancel := context.WithTimeout(r.Context(), adminDeadline)
	defer cancel()
	res, err := h.store.Unban(ctx, UnbanRequest{
		Mode: mode, Scope: scope, Application: input.Application, IP: ip,
		OperationID: input.OperationID, SuppressFor: suppress, Reason: input.Reason,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"state_existed": res.StateExisted, "replayed": res.Replayed,
		"remaining_application_bans_evaluated": res.RemainingApplicationBansEvaluated,
		"nonce":                                res.Nonce, "reset_at_ms": res.ResetAtMS,
		"suppressed_until_ms": res.SuppressedUntilMS, "other_ban": res.OtherBan,
	})
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrOperationConflict):
		http.Error(w, "operation conflict", http.StatusConflict)
	case errors.Is(err, ErrCursorExpired), errors.Is(err, ErrCursorMismatch):
		http.Error(w, err.Error(), http.StatusGone)
	case errors.Is(err, ErrCursorCapacity), errors.Is(err, ErrScanBatchTooLarge):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
	}
}

func writeJSON(w http.ResponseWriter, code int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
