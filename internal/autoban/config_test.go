package autoban

import (
	"testing"
	"time"
)

func testRedisInput() RedisConfig {
	return RedisConfig{
		Addresses:               []string{"127.0.0.1:6379"},
		KeyPrefix:               "test-prefix",
		OperationTimeout:        20 * time.Millisecond,
		RequestStoreBudget:      50 * time.Millisecond,
		MaxConcurrentOperations: 128,
	}
}

func TestAutobanFingerprint(t *testing.T) {
	base := PolicyInput{
		ID: "p1", Enabled: true, Type: "match",
		RuleIDs: []int{1, 2}, RuleTags: []string{"a", "b"},
		Threshold: 3, Window: 60 * time.Second, BanFor: 15 * time.Minute,
	}
	want := fingerprint(base, ScopeApplication)

	reordered := base
	reordered.RuleIDs = []int{2, 1}
	reordered.RuleTags = []string{"b", "a"}
	if got := fingerprint(reordered, ScopeApplication); got != want {
		t.Fatal("selector order must be normalized")
	}

	distinctID := base
	distinctID.ID = "p2"
	if got := fingerprint(distinctID, ScopeApplication); got == want {
		t.Fatal("distinct IDs must produce distinct fingerprints")
	}

	for name, mutate := range map[string]func(*PolicyInput){
		"threshold": func(p *PolicyInput) { p.Threshold = 4 },
		"window":    func(p *PolicyInput) { p.Window = 90 * time.Second },
		"ban":       func(p *PolicyInput) { p.BanFor = 30 * time.Minute },
		"tag":       func(p *PolicyInput) { p.RuleTags = []string{"c"} },
		"score":     func(p *PolicyInput) { v := int64(5); p.MinAnomalyScore = &v },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := fingerprint(changed, ScopeApplication); got == want {
				t.Fatalf("changing %s must alter the fingerprint", name)
			}
		})
	}

	// Global fingerprints are identical regardless of which applications are
	// configured, so a global policy aggregates across applications.
	globalWant := fingerprint(base, ScopeGlobal)
	for _, apps := range [][]ApplicationInput{
		nil,
		{{Name: "a", Enabled: true}},
		{{Name: "b", Enabled: true}, {Name: "c", Enabled: true}},
	} {
		cfg, err := Compile(ConfigInput{
			Enabled: true, Mode: ModeObserve, Redis: testRedisInput(),
			GlobalPolicies: []PolicyInput{base}, Applications: apps,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.globalMatches) != 1 || cfg.globalMatches[0].fingerprint != globalWant {
			t.Fatalf("global fingerprint changed across application sets")
		}
	}
}
