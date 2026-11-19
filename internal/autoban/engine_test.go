package autoban

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// recordingStore captures store commands and returns scripted results.
type recordingStore struct {
	beginCalls   []BeginCommand
	observeCalls []ObserveCommand

	beginResult   BeginResult
	beginErr      error
	observeResult ObserveResult
	observeErr    error
}

func (s *recordingStore) Begin(_ context.Context, cmd BeginCommand) (BeginResult, error) {
	s.beginCalls = append(s.beginCalls, cmd)
	return s.beginResult, s.beginErr
}

func (s *recordingStore) Observe(_ context.Context, cmd ObserveCommand) (ObserveResult, error) {
	s.observeCalls = append(s.observeCalls, cmd)
	return s.observeResult, s.observeErr
}

func (s *recordingStore) Unban(context.Context, UnbanRequest) (UnbanResult, error) {
	return UnbanResult{}, nil
}

func (s *recordingStore) Inspect(context.Context, InspectRequest) (InspectResult, error) {
	return InspectResult{}, nil
}

func (s *recordingStore) List(context.Context, ListRequest) (ListResult, error) {
	return ListResult{}, nil
}

func testSubject(app string, ip string, mode Mode) Subject {
	return Subject{Application: app, IP: netip.MustParseAddr(ip), Mode: mode}
}

func testMeta(app string, ip string, path string, mode Mode) RequestMeta {
	return RequestMeta{
		Subject:   testSubject(app, ip, mode),
		RequestID: RequestID{1, 2, 3},
		Method:    "GET",
		RawPath:   path,
	}
}

func intp(v int64) *int64 { return &v }

func testConfig() Config {
	return Config{
		revision: "rev-1",
		enabled:  true,
		mode:     ModeEnforce,
		limits: storeLimits{
			operationTimeout: 20 * time.Millisecond,
			requestBudget:    50 * time.Millisecond,
			maxConcurrent:    128,
		},
		apps: map[string]*appConfig{
			"app1": {
				enabled: true,
				matches: []matchPolicy{
					{
						id:          "match-1",
						scope:       ScopeApplication,
						fingerprint: "fp-match-1",
						ruleIDs:     []int{100},
						ruleTags:    []string{"attack"},
						threshold:   2,
						windowMS:    60_000,
						banForMS:    60_000,
					},
				},
			},
		},
	}
}

func evidence(matches ...RuleMatch) Evidence {
	return Evidence{Matches: matches, WAFInterrupted: true}
}

func TestEngineDisabledAndExempt(t *testing.T) {
	ip := "203.0.113.10"

	t.Run("disabled top level", func(t *testing.T) {
		cfg := testConfig()
		cfg.enabled = false
		store := &recordingStore{}
		engine, err := newEngineWithClock(cfg, store, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		adm, d := engine.Begin(context.Background(), testMeta("app1", ip, "/", ModeEnforce))
		if len(store.beginCalls) != 0 {
			t.Fatalf("expected zero Begin calls, got %d", len(store.beginCalls))
		}
		if adm.Usable || d.Action != ActionNone {
			t.Fatalf("expected bypass, got usable=%v action=%s", adm.Usable, d.Action)
		}
		engine.Observe(context.Background(), adm, evidence(RuleMatch{ID: 100, Phase: 1}))
		if len(store.observeCalls) != 0 {
			t.Fatalf("expected zero Observe calls, got %d", len(store.observeCalls))
		}
	})

	t.Run("disabled application", func(t *testing.T) {
		cfg := testConfig()
		cfg.apps["app1"].enabled = false
		store := &recordingStore{}
		engine, _ := newEngineWithClock(cfg, store, time.Now)
		engine.Begin(context.Background(), testMeta("app1", ip, "/", ModeEnforce))
		if len(store.beginCalls) != 0 {
			t.Fatalf("expected zero Begin calls, got %d", len(store.beginCalls))
		}
	})

	t.Run("exempt cidr", func(t *testing.T) {
		cfg := testConfig()
		cfg.apps["app1"].exempt = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
		store := &recordingStore{}
		engine, _ := newEngineWithClock(cfg, store, time.Now)
		engine.Begin(context.Background(), testMeta("app1", ip, "/", ModeEnforce))
		if len(store.beginCalls) != 0 {
			t.Fatalf("expected zero Begin calls for exempt IP, got %d", len(store.beginCalls))
		}
	})

	t.Run("unknown application", func(t *testing.T) {
		store := &recordingStore{}
		engine, _ := newEngineWithClock(testConfig(), store, time.Now)
		engine.Begin(context.Background(), testMeta("unknown", ip, "/", ModeEnforce))
		if len(store.beginCalls) != 0 {
			t.Fatalf("expected zero Begin calls for unknown app, got %d", len(store.beginCalls))
		}
	})
}

func TestEngineSelectors(t *testing.T) {
	cfg := testConfig()
	cfg.apps["app1"].matches = []matchPolicy{
		{
			id: "p1", scope: ScopeApplication, fingerprint: "fp1",
			ruleIDs: []int{100}, ruleTags: []string{"attack"},
			threshold: 1, windowMS: 60_000, banForMS: 60_000,
		},
	}
	cfg.globalMatches = []matchPolicy{
		{
			id: "p2", scope: ScopeGlobal, fingerprint: "fp2",
			ruleIDs: []int{200}, ruleTags: []string{"scan"},
			minAnomalyScore: intp(5),
			threshold:       1, windowMS: 60_000, banForMS: 60_000,
		},
	}

	store := &recordingStore{}
	engine, _ := newEngineWithClock(cfg, store, time.Now)
	adm, _ := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeEnforce))
	if !adm.Usable {
		t.Fatal("expected usable admission")
	}

	ev := evidence(
		RuleMatch{ID: 100, Phase: 1},                             // ID match
		RuleMatch{ID: 999, Phase: 2, Tags: []string{"attack"}},   // exact tag match
		RuleMatch{ID: 100, Phase: 3},                             // phase 3 must not count
		RuleMatch{ID: 999, Phase: 2, Tags: []string{"attacker"}}, // non-exact tag
		RuleMatch{ID: 200, Phase: 1},                             // global ID match (score gate)
	)
	ev.AnomalyScore = intp(5)

	engine.Observe(context.Background(), adm, ev)
	if len(store.observeCalls) != 1 {
		t.Fatalf("expected one Observe call, got %d", len(store.observeCalls))
	}
	policies := store.observeCalls[0].Policies
	if len(policies) != 2 {
		t.Fatalf("expected one strike per qualifying policy (2), got %d: %+v", len(policies), policies)
	}
	byID := map[string]MatchSpec{}
	for _, p := range policies {
		byID[p.Ref.ID] = p
	}
	if _, ok := byID["p1"]; !ok {
		t.Fatal("p1 should qualify by ID/tag in phases 1-2")
	}
	if _, ok := byID["p2"]; !ok {
		t.Fatal("p2 should qualify with valid score")
	}

	// score absent/invalid fails score selection for p2
	store.observeCalls = nil
	adm2, _ := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeEnforce))
	ev2 := evidence(RuleMatch{ID: 200, Phase: 1})
	ev2.AnomalyScore = nil
	engine.Observe(context.Background(), adm2, ev2)
	if len(store.observeCalls) != 0 {
		t.Fatalf("nil score must fail score-gated policy, got Observe call")
	}
}

func TestEngineRawPathSelectors(t *testing.T) {
	cfg := testConfig()
	cfg.apps["app1"].rates = []ratePolicy{
		{id: "r1", fingerprint: "fp-r1", requests: 20, periodMS: 10_000, burst: 10,
			methods: []string{"GET"}, pathExact: []string{"/login"}},
		{id: "r2", fingerprint: "fp-r2", requests: 20, periodMS: 10_000, burst: 10,
			methods: []string{"GET"}, pathExact: []string{"/%6cogin"}},
		{id: "r3", fingerprint: "fp-r3", requests: 20, periodMS: 10_000, burst: 10,
			methods: []string{"POST"}, pathPrefix: []string{"/api"}},
	}
	store := &recordingStore{}
	engine, _ := newEngineWithClock(cfg, store, time.Now)

	engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/login", ModeEnforce))
	if got := store.beginCalls[0].Rates; len(got) != 1 || got[0].Ref.Fingerprint != "fp-r1" {
		t.Fatalf("raw /login should select only r1 by fingerprint, got %+v", got)
	}

	store.beginCalls = nil
	engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/%6cogin", ModeEnforce))
	if got := store.beginCalls[0].Rates; len(got) != 1 || got[0].Ref.Fingerprint != "fp-r2" {
		t.Fatalf("/%%6cogin must not be decoded into /login, got %+v", got)
	}

	store.beginCalls = nil
	meta := testMeta("app1", "203.0.113.10", "/api/v1", ModeEnforce)
	meta.Method = "POST"
	engine.Begin(context.Background(), meta)
	if got := store.beginCalls[0].Rates; len(got) != 1 || got[0].Ref.Fingerprint != "fp-r3" {
		t.Fatalf("prefix/method selector should select r3, got %+v", got)
	}
}

func TestEngineShadowStopsEvidence(t *testing.T) {
	ban := BanRecord{
		Subject: testSubject("app1", "203.0.113.10", ModeObserve),
		Ref:     PolicyRef{ID: "p1", Fingerprint: "fp1", Scope: ScopeGlobal},
		Count:   1, WindowMS: 60_000, CreatedAtMS: 1000, ExpiresAtMS: 61_000,
		TriggerRequestID: RequestID{9, 9, 9},
	}

	t.Run("shadow ban", func(t *testing.T) {
		store := &recordingStore{
			beginResult: BeginResult{NowMS: 1000, Bans: []BanRecord{ban}},
		}
		engine, _ := newEngineWithClock(testConfig(), store, time.Now)
		adm, d := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeObserve))
		if d.Action != ActionNone {
			t.Fatalf("observe mode must not enforce, got action=%s", d.Action)
		}
		if d.WouldAction != ActionBan || d.PolicyID != "p1" {
			t.Fatalf("expected would-ban with global explanation, got %+v", d)
		}
		if !adm.ShadowStopped {
			t.Fatal("shadow ban must stop further evidence work")
		}
		engine.Observe(context.Background(), adm, evidence(RuleMatch{ID: 100, Phase: 1}))
		if len(store.observeCalls) != 0 {
			t.Fatalf("shadow ban must suppress all Observe calls, got %d", len(store.observeCalls))
		}
	})

	t.Run("shadow throttle", func(t *testing.T) {
		store := &recordingStore{
			beginResult: BeginResult{NowMS: 1000, ThrottlePolicyID: "r1", RetryAfterSeconds: 2},
		}
		engine, _ := newEngineWithClock(testConfig(), store, time.Now)
		adm, d := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeObserve))
		if d.Action != ActionNone || d.WouldAction != ActionThrottle || d.RetryAfterSeconds != 2 {
			t.Fatalf("expected would-throttle, got %+v", d)
		}
		if !adm.ShadowStopped {
			t.Fatal("shadow throttle must stop further evidence work")
		}
		engine.Observe(context.Background(), adm, evidence(RuleMatch{ID: 100, Phase: 1}))
		if len(store.observeCalls) != 0 {
			t.Fatalf("shadow throttle must suppress all Observe calls, got %d", len(store.observeCalls))
		}
	})
}

func TestEngineAdmissionAge(t *testing.T) {
	base := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	store := &recordingStore{}
	engine, _ := newEngineWithClock(testConfig(), store, clock)
	adm, _ := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeEnforce))

	// exactly 30s reaches the store
	now = base.Add(30 * time.Second)
	engine.Observe(context.Background(), adm, evidence(RuleMatch{ID: 100, Phase: 1}))
	if len(store.observeCalls) != 1 {
		t.Fatalf("age exactly 30s should reach store, got %d calls", len(store.observeCalls))
	}

	// greater than 30s does not
	store.observeCalls = nil
	now = base.Add(30*time.Second + time.Nanosecond)
	engine.Observe(context.Background(), adm, evidence(RuleMatch{ID: 100, Phase: 1}))
	if len(store.observeCalls) != 0 {
		t.Fatalf("age over 30s must not reach store, got %d calls", len(store.observeCalls))
	}

	// unusable admission causes zero Observe calls
	now = base
	store.observeCalls = nil
	badStore := &recordingStore{beginErr: &StoreError{Reason: ReasonTimeout}}
	badEngine, _ := newEngineWithClock(testConfig(), badStore, clock)
	badAdm, badDecision := badEngine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeEnforce))
	if badAdm.Usable || !badDecision.Degraded || badDecision.Reason != ReasonTimeout {
		t.Fatalf("expected degraded unusable admission, got %+v %+v", badAdm, badDecision)
	}
	badEngine.Observe(context.Background(), badAdm, evidence(RuleMatch{ID: 100, Phase: 1}))
	if len(badStore.observeCalls) != 0 {
		t.Fatalf("unusable admission must cause zero Observe calls, got %d", len(badStore.observeCalls))
	}
}

func TestEngineSnapshotIsolation(t *testing.T) {
	cfg := testConfig()
	store := &recordingStore{}
	engine, _ := newEngineWithClock(cfg, store, time.Now)

	// Mutating caller-owned config after capture must not change the snapshot.
	cfg.apps["app1"].matches[0].threshold = 99
	adm, _ := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeEnforce))

	tags := []string{"attack"}
	ev := evidence(RuleMatch{ID: 100, Phase: 1, Tags: tags})
	engine.Observe(context.Background(), adm, ev)
	tags[0] = "changed"
	if got := store.observeCalls[0].Policies[0].Ref.Fingerprint; got != "fp-match-1" {
		t.Fatalf("config mutation leaked into snapshot, fingerprint=%s", got)
	}
	if store.observeCalls[0].Policies[0].Threshold != 2 {
		t.Fatalf("config mutation leaked into threshold")
	}
}

func TestEngineStoreFailureDegrades(t *testing.T) {
	store := &recordingStore{
		beginErr: &StoreError{Reason: ReasonReadOnly, Err: errors.New("read only")},
	}
	engine, _ := newEngineWithClock(testConfig(), store, time.Now)
	_, d := engine.Begin(context.Background(), testMeta("app1", "203.0.113.10", "/", ModeEnforce))
	if !d.Degraded || d.Reason != ReasonReadOnly {
		t.Fatalf("typed store failure must map to degradation, got %+v", d)
	}
}
