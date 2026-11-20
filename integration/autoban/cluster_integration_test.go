//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func resetState(t *testing.T) {
	t.Helper()
	addr := os.Getenv("AUTOBAN_REDIS_ADDR")
	if addr == "" {
		t.Fatal("AUTOBAN_REDIS_ADDR is required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flushing fixture Redis: %v", err)
	}
}

func endpoint(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv("AUTOBAN_HAPROXY_" + name)
	if value == "" {
		t.Fatalf("AUTOBAN_HAPROXY_%s is required", name)
	}
	return value
}

var client = &http.Client{Timeout: 3 * time.Second}

func get(t *testing.T, base, path string) int {
	t.Helper()
	resp, err := client.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", base+path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func post(t *testing.T, base, path string) (*http.Response, int) {
	t.Helper()
	resp, err := client.Post(base+path, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("POST %s: %v", base+path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	defer resp.Body.Close()
	return resp, resp.StatusCode
}

func TestClusterEncodedPaths(t *testing.T) {
	resetState(t)
	a := endpoint(t, "A")
	// The match rule selects the raw path /get. An encoded alias must not be
	// decoded into a match by the policy layer.
	if got := get(t, a, "/%67et"); got != http.StatusOK {
		t.Fatalf("encoded alias status = %d, want 200", got)
	}
}

func TestClusterPersistentConnections(t *testing.T) {
	resetState(t)
	a := endpoint(t, "A")
	for i := 0; i < 2; i++ {
		if got := get(t, a, "/get"); got != http.StatusOK {
			t.Fatalf("keep-alive request %d = %d, want 200", i, got)
		}
	}
	if got := get(t, a, "/get"); got != http.StatusForbidden {
		t.Fatalf("ban must be rechecked on a persistent connection, got %d", got)
	}
}

func TestClusterResponseOwnership(t *testing.T) {
	resetState(t)
	a := endpoint(t, "A")
	if got := get(t, a, "/get"); got != http.StatusOK {
		t.Fatalf("allowed request = %d, want 200", got)
	}
	// The fixture disables response_check; an allowed request must still reach
	// the origin and return a normal response with no policy override.
	resp, err := client.Get(a + "/get")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second allowed request = %d", resp.StatusCode)
	}
}

func TestClusterSharedBan(t *testing.T) {
	resetState(t)
	a, b := endpoint(t, "A"), endpoint(t, "B")
	for i := 0; i < 2; i++ {
		if got := get(t, a, "/get"); got != http.StatusOK {
			t.Fatalf("request %d through A = %d, want 200", i, got)
		}
	}
	if got := get(t, b, "/get"); got != http.StatusForbidden {
		t.Fatalf("third request through B = %d, want 403 across the shared cluster", got)
	}
	if got := get(t, a, "/get"); got != http.StatusForbidden {
		t.Fatalf("later request through A = %d, want 403", got)
	}
}

func TestClusterRates(t *testing.T) {
	resetState(t)
	a, b := endpoint(t, "A"), endpoint(t, "B")
	var throttled *http.Response
	for i := 0; i < 11; i++ {
		base := a
		if i%2 == 1 {
			base = b
		}
		resp, code := post(t, base, "/post")
		if code == http.StatusTooManyRequests {
			throttled = resp
			break
		}
		if code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 or 429", i, code)
		}
	}
	if throttled == nil {
		t.Fatal("shared burst should throttle after 10 accepted requests")
	}
	retry := throttled.Header.Get("Retry-After")
	seconds, err := strconv.ParseInt(retry, 10, 64)
	if err != nil || seconds < 1 {
		t.Fatalf("Retry-After = %q, want positive integer", retry)
	}
}
