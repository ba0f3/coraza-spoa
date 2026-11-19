package autoban

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestAutobanObservability(t *testing.T) {
	RecordDecision("app1", ModeEnforce, Decision{Action: ActionBan, Scope: ScopeApplication, PolicyID: "p1"})
	RecordDecision("app1", ModeEnforce, Decision{Action: ActionNone, Degraded: true, Reason: ReasonTimeout})
	RecordDecision("app1", ModeObserve, Decision{Action: ActionNone, WouldAction: ActionThrottle, RetryAfterSeconds: 2})

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "coraza_autoban_") {
			continue
		}
		seen++
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				value := label.GetValue()
				for _, forbidden := range []string{"203.0.113.10", "request-id", "/login", "secret"} {
					if strings.Contains(value, forbidden) {
						t.Fatalf("metric label %s=%q leaks request data", label.GetName(), value)
					}
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("expected auto-ban metric families")
	}
}

func TestAutobanHealth(t *testing.T) {
	// A disabled configuration records no policy decisions and the config
	// revision label set remains bounded across replacements.
	disabled, err := Compile(ConfigInput{Redis: RedisConfig{
		Addresses: []string{"127.0.0.1:6379"},
	}})
	if err != nil || disabled.Enabled() {
		t.Fatalf("expected disabled config: %v", err)
	}
	SetConfigRevision("rev-a")
	SetConfigRevision("rev-b")
	SetConfigRevision("rev-c")

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "coraza_autoban_config_info" {
			continue
		}
		if len(family.GetMetric()) != 1 {
			t.Fatalf("config-info must expose only the active revision, got %d", len(family.GetMetric()))
		}
	}
}
