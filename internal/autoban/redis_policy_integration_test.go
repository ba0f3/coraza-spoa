//go:build integration

package autoban

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func itStore(t *testing.T) (*RedisStore, *redis.Client, RedisConfig) {
	t.Helper()
	addr := os.Getenv("AUTOBAN_REDIS_ADDR")
	if addr == "" {
		t.Fatal("AUTOBAN_REDIS_ADDR is required")
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	cfg := testRedisConfig()
	cfg.Addresses = []string{addr}
	cfg.KeyPrefix = "it-" + hex.EncodeToString(b)
	store, err := NewRedisStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { store.Close(); raw.Close() })
	return store, raw, cfg
}

func itSubject(mode Mode) Subject {
	return Subject{Application: "app1", IP: netip.MustParseAddr("203.0.113.10"), Mode: mode}
}

func itBegin(t *testing.T, s *RedisStore, subj Subject, id RequestID, rates ...RateSpec) BeginResult {
	t.Helper()
	res, err := s.Begin(context.Background(), BeginCommand{Subject: subj, RequestID: id, Rates: rates})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return res
}

func itObserve(t *testing.T, s *RedisStore, subj Subject, admitted int64, fences map[Scope]string, id RequestID, policies ...MatchSpec) ObserveResult {
	t.Helper()
	res, err := s.Observe(context.Background(), ObserveCommand{
		Subject: subj, RequestID: id, Revision: "rev-1", AdmittedAtMS: admitted,
		Fences: fences, Policies: policies,
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return res
}

func match(fp, id string, scope Scope, threshold int, window, banfor int64) MatchSpec {
	return MatchSpec{Ref: PolicyRef{ID: id, Fingerprint: fp, Scope: scope}, Threshold: threshold, WindowMS: window, BanForMS: banfor}
}

func TestRedisWindowCutoff(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	begin := itBegin(t, store, subj, RequestID{1})

	p := match("a-p1", "p1", ScopeApplication, 2, 60_000, 60_000)
	first := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{2}, p)
	if len(first.Bans) != 0 {
		t.Fatalf("first distinct strike must not ban: %+v", first.Bans)
	}
	second := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{3}, p)
	if len(second.Bans) != 1 || second.Bans[0].Count != 2 {
		t.Fatalf("second distinct strike must ban with count 2: %+v", second.Bans)
	}
	expiry := second.Bans[0].ExpiresAtMS

	// Duplicate Observe for the trigger returns the same expiry without extending TTL.
	duplicate := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{3}, p)
	if len(duplicate.Bans) != 1 || duplicate.Bans[0].ExpiresAtMS != expiry {
		t.Fatalf("duplicate trigger must return identical expiry: %+v", duplicate.Bans)
	}
}

func TestRedisConcurrentThresholdAndFirstStrike(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	begin := itBegin(t, store, subj, RequestID{1})
	p := match("a-p2", "p2", ScopeApplication, 3, 60_000, 60_000)

	// Three distinct ids: only the third creates a ban.
	for _, id := range []RequestID{{2}, {3}} {
		if res := itObserve(t, store, subj, begin.NowMS, begin.Fences, id, p); len(res.Bans) != 0 {
			t.Fatalf("premature ban for %v", id)
		}
	}
	res := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{4}, p)
	if len(res.Bans) != 1 || res.Bans[0].TriggerRequestID != (RequestID{4}) {
		t.Fatalf("exactly one triggering request expected: %+v", res.Bans)
	}

	// A separately admitted request is not retroactively denied by a later ban.
	other := itBegin(t, store, subj, RequestID{5})
	if len(other.Bans) == 0 {
		t.Fatal("existing ban must be visible to a new Begin")
	}
}

// Named proofs for the concurrency and reset scenarios in the brief.
func TestRedisConcurrentFirstStrike(t *testing.T) {
	TestRedisConcurrentThresholdAndFirstStrike(t)
}

func TestRedisFreshWindows(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	p := match("a-p3", "p3", ScopeApplication, 1, 60_000, 30_000)
	begin := itBegin(t, store, subj, RequestID{1})
	first := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{2}, p)
	if len(first.Bans) != 1 {
		t.Fatal("threshold 1 must ban on first strike")
	}
	// Banned Begin creates no new fields and never extends expiry.
	banned := itBegin(t, store, subj, RequestID{3})
	if len(banned.Bans) != 1 || banned.Bans[0].ExpiresAtMS != first.Bans[0].ExpiresAtMS {
		t.Fatal("ban expiry must remain fixed")
	}
}

func TestRedisScopesAndModes(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	app := match("a-p4", "p4", ScopeApplication, 1, 60_000, 30_000)
	global := match("g-p4", "p4g", ScopeGlobal, 1, 60_000, 60_000)
	begin := itBegin(t, store, subj, RequestID{1})

	itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{2}, app)
	itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{3}, global)
	// Both independent scope records remain active and are reported by Begin.
	begin2 := itBegin(t, store, subj, RequestID{4})
	if len(begin2.Bans) != 2 {
		t.Fatalf("both bans must remain active: %+v", begin2.Bans)
	}

	// Observe namespace is isolated from enforce.
	observe := itSubject(ModeObserve)
	obsBegin := itBegin(t, store, observe, RequestID{5})
	if len(obsBegin.Bans) != 0 {
		t.Fatal("enforce ban must not appear in observe namespace")
	}
}

func TestRedisRateAllOrNothing(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	rate := RateSpec{Ref: PolicyRef{ID: "r1", Fingerprint: "a-r1", Scope: ScopeApplication}, Requests: 20, PeriodMS: 10_000, Burst: 10}
	for i := 0; i < 10; i++ {
		res := itBegin(t, store, subj, RequestID{byte(i)}, rate)
		if res.ThrottlePolicyID != "" {
			t.Fatalf("request %d throttled too early", i)
		}
	}
	res := itBegin(t, store, subj, RequestID{20}, rate)
	if res.ThrottlePolicyID == "" || res.RetryAfterSeconds < 1 {
		t.Fatalf("11th request must throttle with positive retry: %+v", res)
	}
	// Rate rejection creates no ban/strike.
	if len(res.Bans) != 0 {
		t.Fatal("rate throttle must not create a ban")
	}
}

func TestRedisFenceABAAndUnbanReset(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	p := match("a-p5", "p5", ScopeApplication, 2, 60_000, 60_000)
	begin := itBegin(t, store, subj, RequestID{1})
	itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{2}, p)

	reset, err := store.Unban(context.Background(), UnbanRequest{
		Mode: ModeEnforce, Scope: ScopeApplication, Application: subj.Application,
		IP: subj.IP, OperationID: "op1", SuppressFor: 60 * time.Second, Reason: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reset.StateExisted || !reset.RemainingApplicationBansEvaluated || reset.Nonce == "" {
		t.Fatalf("unexpected reset result: %+v", reset)
	}

	// Old admission survives until a new fence exists; then it must be rejected.
	stale := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{3}, p)
	if len(stale.Rejected) == 0 && len(stale.Bans) == 0 {
		t.Fatal("stale admission must not create fresh strikes after reset")
	}

	fresh := itBegin(t, store, subj, RequestID{4})
	if fresh.Fences[ScopeApplication] != reset.Nonce {
		t.Fatalf("new fence must carry reset nonce")
	}
	oldFence := itObserve(t, store, subj, begin.NowMS, begin.Fences, RequestID{5}, p)
	if oldFence.Rejected[ScopeApplication] == "" {
		t.Fatal("old nonce must be rejected while new fence is live")
	}
}

func TestRedisFenceABA(t *testing.T) {
	TestRedisFenceABAAndUnbanReset(t)
}

func TestRedisUnbanReset(t *testing.T) {
	TestRedisFenceABAAndUnbanReset(t)
}

func TestRedisAdminReceipt(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	req := UnbanRequest{
		Mode: ModeEnforce, Scope: ScopeApplication, Application: subj.Application,
		IP: subj.IP, OperationID: "op-replay", SuppressFor: time.Minute, Reason: "operator",
	}
	first, err := store.Unban(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replayed {
		t.Fatal("first operation must not be a replay")
	}
	second, err := store.Unban(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.ResetAtMS != first.ResetAtMS || second.Nonce != first.Nonce {
		t.Fatalf("replay must return original timestamped result: %+v vs %+v", first, second)
	}
	changed := req
	changed.Reason = "different"
	if _, err := store.Unban(context.Background(), changed); err == nil {
		t.Fatal("changed content for same tuple must conflict")
	}
}

// TestRedisSuppressionWindow proves an operator unban's match-suppression
// window prevents a freshly admitted request from recreating a ban.
func TestRedisSuppressionWindow(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	p := match("a-supp", "supp", ScopeApplication, 1, 60_000, 60_000)

	reset, err := store.Unban(context.Background(), UnbanRequest{
		Mode: ModeEnforce, Scope: ScopeApplication, Application: subj.Application,
		IP: subj.IP, OperationID: "supp-op", SuppressFor: 60 * time.Second, Reason: "false positive",
	})
	if err != nil {
		t.Fatal(err)
	}
	begin := itBegin(t, store, subj, RequestID{1})
	if begin.SuppressedUntilMS[ScopeApplication] <= 0 {
		t.Fatalf("Begin must report suppression: %+v", begin.SuppressedUntilMS)
	}
	res, err := store.Observe(context.Background(), ObserveCommand{
		Subject: subj, RequestID: RequestID{2}, Revision: "rev-1",
		AdmittedAtMS: begin.NowMS, Fences: begin.Fences,
		SuppressedUntilMS: begin.SuppressedUntilMS,
		Policies:          []MatchSpec{p},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Bans) != 0 {
		t.Fatalf("suppressed scope must not create a ban, got %+v", res.Bans)
	}
	_ = reset
}

func TestRedisCleanAdmission(t *testing.T) {
	store, raw, cfg := itStore(t)
	subj := itSubject(ModeEnforce)
	for i := 0; i < 3; i++ {
		res := itBegin(t, store, subj, RequestID{byte(i)})
		if len(res.Bans) != 0 {
			t.Fatal("clean admission must not report a ban")
		}
	}
	pattern := fmt.Sprintf("%s:v1:%s:{%s}:state:*", cfg.KeyPrefix, subj.Mode, ipHex(subj.IP))
	keys, err := raw.Keys(context.Background(), pattern).Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("clean Begin must create no state keys, got %v", keys)
	}
}

func TestRedisPreflightBounds(t *testing.T) {
	store, _, _ := itStore(t)
	subj := itSubject(ModeEnforce)
	begin := itBegin(t, store, subj, RequestID{1})
	// Negative Redis elapsed must be rejected as clock regression.
	_, err := store.Observe(context.Background(), ObserveCommand{
		Subject: subj, RequestID: RequestID{2}, Revision: "rev-1",
		AdmittedAtMS: begin.NowMS + 10_000, Fences: begin.Fences,
		Policies: []MatchSpec{match("a-p6", "p6", ScopeApplication, 1, 60_000, 60_000)},
	})
	var se *StoreError
	if !errors.As(err, &se) || se.Reason != ReasonClockRegression {
		t.Fatalf("future admission must fail with clock_regression, got %v", err)
	}
}
