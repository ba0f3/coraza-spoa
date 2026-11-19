package autoban

import (
	"net/netip"
	"strings"
	"time"
)

// Config is a deeply copied, immutable compiled policy snapshot. All state is
// private: only Compile (same package) constructs it.
type Config struct {
	revision      string
	enabled       bool
	mode          Mode
	apps          map[string]*appConfig
	globalMatches []matchPolicy
	limits        storeLimits
	redis         RedisConfig
}

// RedisConfig returns the resolved, secret-bearing Redis settings. It is kept
// private on Config so request code cannot mutate connection settings.
func (c Config) RedisConfig() RedisConfig { return c.redis }

// Enabled reports whether auto-ban participates in requests.
func (c Config) Enabled() bool { return c.enabled }

// Mode reports the top-level effective mode.
func (c Config) Mode() Mode { return c.mode }

// Revision identifies the active configuration across nodes.
func (c Config) Revision() string { return c.revision }

// OperationTimeout reports the per-operation store timeout.
func (c Config) OperationTimeout() time.Duration { return c.limits.operationTimeout }

// RequestStoreBudget reports the total per-request store budget.
func (c Config) RequestStoreBudget() time.Duration { return c.limits.requestBudget }

// MaxConcurrentOperations reports the per-process concurrency limit.
func (c Config) MaxConcurrentOperations() int { return c.limits.maxConcurrent }

// GlobalPolicyCount reports the number of enabled global match policies.
func (c Config) GlobalPolicyCount() int { return len(c.globalMatches) }

type appConfig struct {
	enabled bool
	mode    Mode
	exempt  []netip.Prefix
	matches []matchPolicy
	rates   []ratePolicy
}

type storeLimits struct {
	operationTimeout time.Duration
	requestBudget    time.Duration
	maxConcurrent    int
}

type matchPolicy struct {
	id              string
	scope           Scope
	fingerprint     string
	ruleIDs         []int
	ruleTags        []string
	minAnomalyScore *int64
	threshold       int
	windowMS        int64
	banForMS        int64
}

type ratePolicy struct {
	id          string
	fingerprint string
	requests    int64
	periodMS    int64
	burst       int64
	methods     []string
	pathExact   []string
	pathPrefix  []string
}

// cloneConfig deep-copies a compiled snapshot so caller mutation cannot alter
// an operation that captured it.
func cloneConfig(in Config) Config {
	out := in
	out.apps = make(map[string]*appConfig, len(in.apps))
	for name, app := range in.apps {
		if app == nil {
			continue
		}
		clone := *app
		clone.exempt = append([]netip.Prefix(nil), app.exempt...)
		clone.matches = cloneMatches(app.matches)
		clone.rates = cloneRates(app.rates)
		out.apps[name] = &clone
	}
	out.globalMatches = cloneMatches(in.globalMatches)
	return out
}

func cloneMatches(in []matchPolicy) []matchPolicy {
	out := make([]matchPolicy, len(in))
	for i, p := range in {
		out[i] = p
		out[i].ruleIDs = append([]int(nil), p.ruleIDs...)
		out[i].ruleTags = append([]string(nil), p.ruleTags...)
		if p.minAnomalyScore != nil {
			v := *p.minAnomalyScore
			out[i].minAnomalyScore = &v
		}
	}
	return out
}

func cloneRates(in []ratePolicy) []ratePolicy {
	out := make([]ratePolicy, len(in))
	for i, p := range in {
		out[i] = p
		out[i].methods = append([]string(nil), p.methods...)
		out[i].pathExact = append([]string(nil), p.pathExact...)
		out[i].pathPrefix = append([]string(nil), p.pathPrefix...)
	}
	return out
}

func cloneEvidence(in Evidence) Evidence {
	out := in
	out.Matches = make([]RuleMatch, len(in.Matches))
	for i, m := range in.Matches {
		out.Matches[i] = m
		out.Matches[i].Tags = append([]string(nil), m.Tags...)
	}
	if in.AnomalyScore != nil {
		v := *in.AnomalyScore
		out.AnomalyScore = &v
	}
	return out
}

func cloneFences(in map[Scope]string) map[Scope]string {
	out := make(map[Scope]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// effectiveMode resolves an application override against the top-level mode.
func (c Config) effectiveMode(app *appConfig) Mode {
	if app != nil && app.mode != "" {
		return app.mode
	}
	if c.mode != "" {
		return c.mode
	}
	return ModeObserve
}

// eligibleApps reports whether an application participates in auto-ban.
func (c Config) eligibleApp(name string) (*appConfig, bool) {
	if !c.enabled {
		return nil, false
	}
	app, ok := c.apps[name]
	if !ok || app == nil || !app.enabled {
		return nil, false
	}
	return app, true
}

// isExempt reports whether an address is in an application's exemption set.
func isExempt(app *appConfig, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	addr := ip.Unmap()
	for _, p := range app.exempt {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// selectRates builds the rate specs whose method/path selectors match meta.
func selectRates(app *appConfig, meta RequestMeta) []RateSpec {
	var out []RateSpec
	for _, p := range app.rates {
		if !methodMatches(p, meta.Method) || !pathMatches(p, meta.RawPath) {
			continue
		}
		out = append(out, RateSpec{
			Ref:      PolicyRef{ID: p.id, Fingerprint: p.fingerprint, Scope: ScopeApplication},
			Requests: p.requests,
			PeriodMS: p.periodMS,
			Burst:    p.burst,
		})
	}
	return out
}

func methodMatches(p ratePolicy, method string) bool {
	if len(p.methods) == 0 {
		return true
	}
	for _, m := range p.methods {
		if m == method {
			return true
		}
	}
	return false
}

// pathMatches compares HAProxy's raw path literally: no decoding is performed.
func pathMatches(p ratePolicy, rawPath string) bool {
	if len(p.pathExact) == 0 && len(p.pathPrefix) == 0 {
		return true
	}
	for _, path := range p.pathExact {
		if rawPath == path {
			return true
		}
	}
	for _, prefix := range p.pathPrefix {
		if strings.HasPrefix(rawPath, prefix) {
			return true
		}
	}
	return false
}

// selectMatches builds one strike per qualifying policy. Score requirements
// are an AND condition: a nil/invalid score fails selection.
func (c Config) selectMatches(app *appConfig, ev Evidence) []MatchSpec {
	var policies []matchPolicy
	if app != nil {
		policies = append(policies, app.matches...)
	}
	policies = append(policies, c.globalMatches...)

	var out []MatchSpec
	for _, p := range policies {
		if !policyQualifies(p, ev) {
			continue
		}
		out = append(out, MatchSpec{
			Ref:       PolicyRef{ID: p.id, Fingerprint: p.fingerprint, Scope: p.scope},
			Threshold: p.threshold,
			WindowMS:  p.windowMS,
			BanForMS:  p.banForMS,
		})
	}
	return out
}

func policyQualifies(p matchPolicy, ev Evidence) bool {
	qualified := false
	for _, m := range ev.Matches {
		if m.Phase != 1 && m.Phase != 2 {
			continue
		}
		if containsInt(p.ruleIDs, m.ID) || containsExact(p.ruleTags, m.Tags) {
			qualified = true
			break
		}
	}
	if !qualified {
		return false
	}
	if p.minAnomalyScore != nil {
		if ev.AnomalyScore == nil || *ev.AnomalyScore < *p.minAnomalyScore {
			return false
		}
	}
	return true
}

func containsInt(values []int, want int) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func containsExact(values []string, tags []string) bool {
	for _, want := range values {
		for _, tag := range tags {
			if tag == want {
				return true
			}
		}
	}
	return false
}
