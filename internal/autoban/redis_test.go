package autoban

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeRedis implements only the commands the adapter uses. It records calls
// and lets tests inject replies and errors.
type fakeRedis struct {
	evalCalls    int
	evalShaCalls int
	loadCalls    int
	evalErr      error
	shaErr       error
	loadErr      error
	delay        time.Duration
	deadlines    []time.Time
}

func (f *fakeRedis) Eval(ctx context.Context, _ string, _ []string, _ ...interface{}) *redis.Cmd {
	f.evalCalls++
	recordDeadline(f, ctx)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
		}
	}
	cmd := redis.NewCmd(ctx)
	if f.evalErr != nil {
		cmd.SetErr(f.evalErr)
	} else {
		cmd.SetVal([]interface{}{int64(0)})
	}
	return cmd
}

func (f *fakeRedis) EvalSha(ctx context.Context, _ string, _ []string, _ ...interface{}) *redis.Cmd {
	f.evalShaCalls++
	recordDeadline(f, ctx)
	cmd := redis.NewCmd(ctx)
	if f.shaErr != nil {
		cmd.SetErr(f.shaErr)
	} else {
		cmd.SetVal([]interface{}{int64(0)})
	}
	return cmd
}

func (f *fakeRedis) ScriptLoad(ctx context.Context, _ string) *redis.StringCmd {
	f.loadCalls++
	recordDeadline(f, ctx)
	cmd := redis.NewStringCmd(ctx)
	if f.loadErr != nil {
		cmd.SetErr(f.loadErr)
	} else {
		cmd.SetVal("sha")
	}
	return cmd
}

func (f *fakeRedis) Time(ctx context.Context) *redis.TimeCmd {
	cmd := redis.NewTimeCmd(ctx)
	cmd.SetVal(time.Unix(1_700_000_000, 0))
	return cmd
}

func (f *fakeRedis) Close() error { return nil }

func recordDeadline(f *fakeRedis, ctx context.Context) {
	if d, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, d)
	}
}

func testRedisConfig() RedisConfig {
	return RedisConfig{
		Addresses:               []string{"127.0.0.1:6379"},
		KeyPrefix:               "test-prefix",
		OperationTimeout:        50 * time.Millisecond,
		RequestStoreBudget:      50 * time.Millisecond,
		MaxConcurrentOperations: 128,
	}
}

func TestRedisKeys(t *testing.T) {
	v4 := netip.MustParseAddr("203.0.113.10")
	mapped := netip.MustParseAddr("::ffff:203.0.113.10")
	if ipHex(v4) != ipHex(mapped) {
		t.Fatal("mapped IPv4 must share its IPv4 subject")
	}
	if stateKey("p", ModeEnforce, ScopeApplication, "app", v4) == stateKey("p", ModeObserve, ScopeApplication, "app", v4) {
		t.Fatal("modes must be isolated")
	}
	if stateKey("p", ModeEnforce, ScopeGlobal, "", v4) == stateKey("p", ModeEnforce, ScopeApplication, "app", v4) {
		t.Fatal("scopes must be isolated")
	}
	if encodeApp("a_b") == encodeApp("ab") && len("a_b") != len("ab") {
		t.Fatal("app encoding must be collision-free")
	}
	for _, name := range []string{"a", "ab", "a_b", "app-1", strings.Repeat("x", 64)} {
		if encodeApp(name) == encodeApp(name+"x") {
			t.Fatalf("app encoding collision for %q", name)
		}
	}
	// Keys never contain raw request metadata: the key builders accept only
	// identity fields, so no raw path or header can reach a key.
	key := stateKey("p", ModeEnforce, ScopeApplication, "app", v4)
	if strings.Contains(key, "/") || strings.Contains(key, "User-Agent") {
		t.Fatalf("unexpected request metadata in key: %s", key)
	}
	_ = fenceKey("p", ModeEnforce, ScopeGlobal, "", v4)
	_ = adminKey("p", ModeEnforce, v4, adminScopeID(ScopeGlobal, ""), "op1")
}

func TestRedisBudgetAndNoReplay(t *testing.T) {
	t.Run("budget subtraction", func(t *testing.T) {
		got := remainingAfter(50*time.Millisecond, 40*time.Millisecond)
		if got != 10*time.Millisecond {
			t.Fatalf("remaining = %s, want 10ms", got)
		}
		if got := remainingAfter(10*time.Millisecond, 40*time.Millisecond); got != 0 {
			t.Fatalf("remaining must clamp to zero, got %s", got)
		}
	})

	t.Run("operation deadline is min of timeout remaining and parent", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		ctx, stop := operationDeadline(parent, 50*time.Millisecond, 10*time.Millisecond)
		defer stop()
		d, ok := ctx.Deadline()
		if !ok || time.Until(d) > 10*time.Millisecond {
			t.Fatalf("deadline must honor remaining budget, got %v", d)
		}
	})

	t.Run("intervening WAF time does not consume budget", func(t *testing.T) {
		budget := newBudget(50 * time.Millisecond)
		start := time.Now()
		_, stop := budget.slice(context.Background(), 50*time.Millisecond)
		time.Sleep(20 * time.Millisecond)
		budget.consume(start)
		if budget.remaining < 25*time.Millisecond {
			t.Fatalf("idle time must not consume store budget, remaining %s", budget.remaining)
		}
		stop()
	})

	t.Run("saturation returns immediately", func(t *testing.T) {
		store := newRedisStoreWithClient(testRedisConfig(), &fakeRedis{})
		store.sem = make(chan struct{}, 1)
		store.sem <- struct{}{}
		start := time.Now()
		err := store.acquire(context.Background())
		if err == nil {
			t.Fatal("expected saturation error")
		}
		var se *StoreError
		if !errors.As(err, &se) || se.Reason != ReasonSaturated {
			t.Fatalf("expected saturated StoreError, got %v", err)
		}
		if time.Since(start) > 10*time.Millisecond {
			t.Fatal("saturation must not wait")
		}
	})

	t.Run("ambiguous timeout performs one command attempt", func(t *testing.T) {
		fake := &fakeRedis{evalErr: context.DeadlineExceeded}
		store := newRedisStoreWithClient(testRedisConfig(), fake)
		_, err := store.eval(context.Background(), "return 0", nil, nil, true)
		var se *StoreError
		if !errors.As(err, &se) || se.Reason != ReasonTimeout || !se.Uncertain {
			t.Fatalf("expected uncertain timeout, got %v", err)
		}
		if fake.evalCalls != 1 {
			t.Fatalf("ambiguous timeout must not replay, got %d attempts", fake.evalCalls)
		}
	})

	t.Run("NOSCRIPT recovery shares original deadline", func(t *testing.T) {
		fake := &fakeRedis{shaErr: redis.Nil}
		store := newRedisStoreWithClient(testRedisConfig(), fake)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, _ = store.evalWithScript(ctx, "return 0", nil, nil)
		if fake.evalShaCalls < 2 || fake.loadCalls != 1 {
			t.Fatalf("expected sha, load, sha recovery: sha=%d load=%d", fake.evalShaCalls, fake.loadCalls)
		}
		if len(fake.deadlines) < 2 || !fake.deadlines[0].Equal(fake.deadlines[len(fake.deadlines)-1]) {
			t.Fatal("NOSCRIPT recovery must share the original deadline")
		}
	})
}

func TestRedisFailures(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		want      Reason
		uncertain bool
	}{
		{"disconnect", errors.New("connection refused"), ReasonConnection, false},
		{"read only", errors.New("READONLY You can't write"), ReasonReadOnly, false},
		{"oom", errors.New("OOM command not allowed"), ReasonOOM, false},
		{"wrong type", errors.New("WRONGTYPE Operation against a key"), ReasonWrongType, false},
		{"malformed reply", errors.New("redis: can't parse reply"), ReasonMalformedReply, false},
		{"canceled", context.Canceled, ReasonTimeout, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newRedisStoreWithClient(testRedisConfig(), &fakeRedis{evalErr: tc.err})
			_, err := store.eval(context.Background(), "return 0", nil, nil, true)
			var se *StoreError
			if !errors.As(err, &se) || se.Reason != tc.want {
				t.Fatalf("got %v, want reason %s", err, tc.want)
			}
			if se.Uncertain != tc.uncertain {
				t.Fatalf("uncertain=%t, want %t", se.Uncertain, tc.uncertain)
			}
		})
	}
}
