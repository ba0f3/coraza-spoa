package autoban

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

const (
	defaultKeyPrefix     = "coraza-autoban"
	defaultOperationTO   = 20 * time.Millisecond
	defaultStoreBudget   = 50 * time.Millisecond
	defaultMaxConcurrent = 128

	maxWindow       = time.Hour
	minWindow       = 30 * time.Second
	maxBanFor       = 24 * time.Hour
	minBanFor       = 30 * time.Second
	maxThreshold    = 256
	maxPeriod       = time.Hour
	minPeriod       = time.Millisecond
	maxRequestsPerS = 10000
	maxBurst        = 10000
	maxPolicies     = 32
	maxFields       = 64
)

// ConfigInput is the validated-YAML-independent input to Compile.
type ConfigInput struct {
	Enabled                 bool
	Mode                    Mode
	OnStoreError            string
	Redis                   RedisConfig
	OperationTimeout        time.Duration
	RequestStoreBudget      time.Duration
	MaxConcurrentOperations int
	GlobalPolicies          []PolicyInput
	Applications            []ApplicationInput
}

// ApplicationInput is one participating application's policy block.
type ApplicationInput struct {
	Name        string
	Enabled     bool
	Mode        Mode
	ExemptCIDRs []string
	Policies    []PolicyInput
}

// PolicyInput is one match or rate policy declaration.
type PolicyInput struct {
	ID              string
	Enabled         bool
	Type            string
	RuleTags        []string
	RuleIDs         []int
	MinAnomalyScore *int64
	Threshold       int
	Window          time.Duration
	BanFor          time.Duration
	Methods         []string
	PathExact       []string
	PathPrefix      []string
	Requests        int64
	Period          time.Duration
	Burst           int64
}

// TLSConfig holds TLS settings; verification is always enabled.
type TLSConfig struct {
	Enabled    bool
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
}

// RedisConfig holds connection, TLS, secret, and store-timing settings.
type RedisConfig struct {
	Addresses               []string
	MasterName              string
	Username                string
	PasswordFile            string
	Password                string
	SentinelUsername        string
	SentinelPasswordFile    string
	SentinelPassword        string
	DB                      int
	KeyPrefix               string
	TLS                     TLSConfig
	OperationTimeout        time.Duration
	RequestStoreBudget      time.Duration
	MaxConcurrentOperations int
}

// Compile validates all inputs and produces an immutable Config plus the
// resolved Redis settings. It never opens a connection or listener; when the
// feature is disabled it never reads a secret file either.
func Compile(input ConfigInput) (Config, error) {
	opTimeout := input.OperationTimeout
	if opTimeout == 0 {
		opTimeout = defaultOperationTO
	}
	budget := input.RequestStoreBudget
	if budget == 0 {
		budget = defaultStoreBudget
	}
	concurrency := input.MaxConcurrentOperations
	if concurrency == 0 {
		concurrency = defaultMaxConcurrent
	}

	redis := input.Redis
	if redis.KeyPrefix == "" {
		redis.KeyPrefix = defaultKeyPrefix
	}
	if redis.OperationTimeout == 0 {
		redis.OperationTimeout = opTimeout
	}
	if redis.RequestStoreBudget == 0 {
		redis.RequestStoreBudget = budget
	}
	if redis.MaxConcurrentOperations == 0 {
		redis.MaxConcurrentOperations = concurrency
	}

	mode := input.Mode
	if mode == "" {
		mode = ModeObserve
	}

	cfg := Config{
		enabled: input.Enabled,
		mode:    mode,
		limits: storeLimits{
			operationTimeout: opTimeout,
			requestBudget:    budget,
			maxConcurrent:    concurrency,
		},
		apps: make(map[string]*appConfig),
	}
	if !input.Enabled {
		cfg.redis = redis
		cfg.revision = revisionFor(input, mode, opTimeout, budget, concurrency)
		return cfg, nil
	}

	if mode != ModeObserve && mode != ModeEnforce {
		return Config{},
			fmt.Errorf("autoban: invalid mode %q", mode)
	}
	if input.OnStoreError != "" && input.OnStoreError != "continue_waf" {
		return Config{},
			fmt.Errorf("autoban: unsupported on_store_error %q", input.OnStoreError)
	}
	if opTimeout < time.Millisecond || opTimeout > 100*time.Millisecond {
		return Config{},
			fmt.Errorf("autoban: operation_timeout out of range")
	}
	if budget < opTimeout || budget > 200*time.Millisecond {
		return Config{},
			fmt.Errorf("autoban: request_store_budget out of range")
	}
	if concurrency <= 0 {
		return Config{},
			fmt.Errorf("autoban: max_concurrent_operations must be positive")
	}

	if err := validateRedis(&redis); err != nil {
		return Config{},
			err
	}
	if err := readSecrets(&redis); err != nil {
		return Config{},
			err
	}

	// Compile participating applications.
	seenApps := map[string]struct{}{}
	totalFingerprints := map[string]struct{}{}
	for _, app := range input.Applications {
		if !app.Enabled {
			continue
		}
		if err := validateAppName(app.Name); err != nil {
			return Config{},
				err
		}
		if _, dup := seenApps[app.Name]; dup {
			return Config{},
				fmt.Errorf("autoban: duplicate application %q", app.Name)
		}
		seenApps[app.Name] = struct{}{}

		appMode := app.Mode
		if appMode != "" && appMode != ModeObserve && appMode != ModeEnforce {
			return Config{},
				fmt.Errorf("autoban: invalid mode for app %q", app.Name)
		}

		compiled := &appConfig{enabled: true, mode: appMode}
		for _, cidr := range app.ExemptCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return Config{},
					fmt.Errorf("autoban: invalid exempt CIDR %q", cidr)
			}
			compiled.exempt = append(compiled.exempt, prefix)
		}
		matches, rates, err := compilePolicies(app.Policies, ScopeApplication, totalFingerprints)
		if err != nil {
			return Config{},
				fmt.Errorf("autoban: app %q: %w", app.Name, err)
		}
		compiled.matches, compiled.rates = matches, rates
		if len(matches)+len(rates) > maxPolicies {
			return Config{},
				fmt.Errorf("autoban: app %q exceeds %d policies", app.Name, maxPolicies)
		}
		cfg.apps[app.Name] = compiled
	}

	global, _, err := compilePolicies(input.GlobalPolicies, ScopeGlobal, totalFingerprints)
	if err != nil {
		return Config{},
			fmt.Errorf("autoban: global policies: %w", err)
	}
	for _, m := range global {
		if m.fingerprint == "" {
			return Config{},
				fmt.Errorf("autoban: global policy must be a match policy")
		}
	}
	if len(global) > maxPolicies {
		return Config{},
			fmt.Errorf("autoban: too many global policies")
	}
	cfg.globalMatches = global

	if len(totalFingerprints) > maxFields {
		return Config{},
			fmt.Errorf("autoban: too many distinct policy fields")
	}

	cfg.redis = redis
	cfg.revision = revisionFor(input, mode, opTimeout, budget, concurrency)
	return cfg, nil
}

func validateAppName(name string) error {
	if name == "" {
		return fmt.Errorf("autoban: empty application name")
	}
	if utf8.RuneCountInString(name) > 256 && len(name) > 256 {
		return fmt.Errorf("autoban: application name exceeds 256 UTF-8 bytes")
	}
	if len(name) > 256 {
		return fmt.Errorf("autoban: application name exceeds 256 UTF-8 bytes")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("autoban: control character in application name")
		}
	}
	return nil
}

func validateRedis(redis *RedisConfig) error {
	if !idPattern.MatchString(redis.KeyPrefix) {
		return fmt.Errorf("autoban: invalid key_prefix")
	}
	if redis.DB < 0 {
		return fmt.Errorf("autoban: invalid redis db")
	}
	if redis.MasterName == "" {
		if len(redis.Addresses) != 1 {
			return fmt.Errorf("autoban: standalone Redis requires exactly one address")
		}
	} else {
		if len(redis.Addresses) == 0 {
			return fmt.Errorf("autoban: Sentinel requires at least one address")
		}
	}
	tls := redis.TLS
	if tls.Enabled {
		if (tls.CertFile == "") != (tls.KeyFile == "") {
			return fmt.Errorf("autoban: incomplete TLS certificate/key pair")
		}
		// Verification is mandatory; server_name may be supplied for SNI.
	}
	if redis.OperationTimeout < time.Millisecond || redis.OperationTimeout > 100*time.Millisecond {
		return fmt.Errorf("autoban: redis operation timeout out of range")
	}
	if redis.RequestStoreBudget < redis.OperationTimeout || redis.RequestStoreBudget > 200*time.Millisecond {
		return fmt.Errorf("autoban: redis request store budget out of range")
	}
	if redis.MaxConcurrentOperations <= 0 {
		return fmt.Errorf("autoban: redis concurrency must be positive")
	}
	return nil
}

func readSecrets(redis *RedisConfig) error {
	var err error
	if redis.PasswordFile != "" {
		redis.Password, err = readSecret(redis.PasswordFile)
		if err != nil {
			return fmt.Errorf("autoban: redis password: %w", err)
		}
	}
	if redis.SentinelPasswordFile != "" {
		redis.SentinelPassword, err = readSecret(redis.SentinelPasswordFile)
		if err != nil {
			return fmt.Errorf("autoban: sentinel password: %w", err)
		}
	}
	for _, path := range []string{redis.TLS.CAFile, redis.TLS.CertFile, redis.TLS.KeyFile} {
		if path != "" {
			if _, err := os.ReadFile(path); err != nil {
				return fmt.Errorf("autoban: TLS file: %w", err)
			}
		}
	}
	return nil
}

// readSecret trims exactly one trailing newline and rejects embedded NUL.
func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, c := range b {
		if c == 0 {
			return "", fmt.Errorf("secret file contains NUL")
		}
	}
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return string(b), nil
}

func compilePolicies(inputs []PolicyInput, scope Scope, fingerprints map[string]struct{}) ([]matchPolicy, []ratePolicy, error) {
	var matches []matchPolicy
	var rates []ratePolicy
	seenIDs := map[string]struct{}{}
	for _, p := range inputs {
		if !p.Enabled {
			continue
		}
		if p.ID == "" {
			return nil, nil, fmt.Errorf("autoban: policy must have an id")
		}
		if !idPattern.MatchString(p.ID) {
			return nil, nil, fmt.Errorf("autoban: invalid policy id %q", p.ID)
		}
		if _, dup := seenIDs[p.ID]; dup {
			return nil, nil, fmt.Errorf("autoban: duplicate policy id %q", p.ID)
		}
		seenIDs[p.ID] = struct{}{}

		switch p.Type {
		case "match":
			if p.Requests != 0 || p.Period != 0 || p.Burst != 0 || len(p.Methods) != 0 || len(p.PathExact) != 0 || len(p.PathPrefix) != 0 {
				return nil, nil, fmt.Errorf("autoban: mixed policy-type fields in %q", p.ID)
			}
			if len(p.RuleIDs) == 0 && len(p.RuleTags) == 0 {
				return nil, nil, fmt.Errorf("autoban: empty match selectors in %q", p.ID)
			}
			if p.Threshold < 1 || p.Threshold > maxThreshold {
				return nil, nil, fmt.Errorf("autoban: threshold out of range in %q", p.ID)
			}
			if p.Window < minWindow || p.Window > maxWindow {
				return nil, nil, fmt.Errorf("autoban: window out of range in %q", p.ID)
			}
			if p.BanFor < minBanFor || p.BanFor > maxBanFor {
				return nil, nil, fmt.Errorf("autoban: ban_for out of range in %q", p.ID)
			}
			if scope == ScopeGlobal && p.MinAnomalyScore == nil && len(p.RuleIDs) == 0 && len(p.RuleTags) == 0 {
				return nil, nil, fmt.Errorf("autoban: global match needs selectors")
			}
			fp := fingerprint(p, scope)
			fingerprints[fp] = struct{}{}
			mp := matchPolicy{
				id: p.ID, scope: scope, fingerprint: fp,
				ruleIDs:         append([]int(nil), p.RuleIDs...),
				ruleTags:        append([]string(nil), p.RuleTags...),
				minAnomalyScore: p.MinAnomalyScore,
				threshold:       p.Threshold,
				windowMS:        p.Window.Milliseconds(),
				banForMS:        p.BanFor.Milliseconds(),
			}
			if p.MinAnomalyScore != nil {
				v := *p.MinAnomalyScore
				mp.minAnomalyScore = &v
			}
			matches = append(matches, mp)
		case "rate":
			if scope == ScopeGlobal {
				return nil, nil, fmt.Errorf("autoban: global rate policies are not supported")
			}
			if len(p.RuleIDs) != 0 || len(p.RuleTags) != 0 || p.MinAnomalyScore != nil || p.Threshold != 0 || p.Window != 0 || p.BanFor != 0 {
				return nil, nil, fmt.Errorf("autoban: mixed policy-type fields in %q", p.ID)
			}
			if p.Requests <= 0 || p.Burst < 1 || p.Burst > maxBurst {
				return nil, nil, fmt.Errorf("autoban: rate values out of range in %q", p.ID)
			}
			if p.Period < minPeriod || p.Period > maxPeriod || p.Period%time.Millisecond != 0 {
				return nil, nil, fmt.Errorf("autoban: period out of range in %q", p.ID)
			}
			periodMS := p.Period.Milliseconds()
			if float64(p.Requests)*1000/float64(periodMS) > maxRequestsPerS {
				return nil, nil, fmt.Errorf("autoban: refill rate too high in %q", p.ID)
			}
			fp := fingerprint(p, scope)
			fingerprints[fp] = struct{}{}
			rates = append(rates, ratePolicy{
				id: p.ID, fingerprint: fp, requests: p.Requests,
				periodMS: periodMS, burst: p.Burst,
				methods:    append([]string(nil), p.Methods...),
				pathExact:  append([]string(nil), p.PathExact...),
				pathPrefix: append([]string(nil), p.PathPrefix...),
			})
		default:
			return nil, nil, fmt.Errorf("autoban: unknown policy type %q", p.Type)
		}
	}
	return matches, rates, nil
}

// fingerprint is SHA-256 over canonical policy semantics, including the
// configured ID. Selector order is normalized; the application is excluded so
// a global policy aggregates across applications.
func fingerprint(p PolicyInput, scope Scope) string {
	var b strings.Builder
	b.WriteString("v1|")
	b.WriteString(string(scope))
	b.WriteString("|")
	b.WriteString(p.Type)
	b.WriteString("|")
	b.WriteString(p.ID)
	b.WriteString("|")
	if p.Type == "match" {
		ids := append([]int(nil), p.RuleIDs...)
		sort.Ints(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "id:%d,", id)
		}
		tags := append([]string(nil), p.RuleTags...)
		sort.Strings(tags)
		for _, tag := range tags {
			fmt.Fprintf(&b, "tag:%s,", tag)
		}
		if p.MinAnomalyScore != nil {
			fmt.Fprintf(&b, "score:%d,", *p.MinAnomalyScore)
		}
		fmt.Fprintf(&b, "threshold:%d,window:%d,ban:%d", p.Threshold, p.Window.Milliseconds(), p.BanFor.Milliseconds())
	} else {
		for _, key := range [][]string{p.Methods, p.PathExact, p.PathPrefix} {
			values := append([]string(nil), key...)
			sort.Strings(values)
			for _, v := range values {
				fmt.Fprintf(&b, "%s,", v)
			}
			b.WriteString("|")
		}
		fmt.Fprintf(&b, "requests:%d,period:%d,burst:%d", p.Requests, p.Period.Milliseconds(), p.Burst)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func revisionFor(input ConfigInput, mode Mode, op, budget time.Duration, concurrency int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%t|%s|%s|%d|%d|%d|", input.Enabled, mode, input.OnStoreError, op, budget, concurrency)
	fmt.Fprintf(&b, "%s|%s|%v|", input.Redis.KeyPrefix, input.Redis.MasterName, input.Redis.Addresses)
	apps := append([]ApplicationInput(nil), input.Applications...)
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	for _, app := range apps {
		fmt.Fprintf(&b, "app:%s:%t:%s|", app.Name, app.Enabled, app.Mode)
	}
	for _, p := range input.GlobalPolicies {
		fmt.Fprintf(&b, "global:%s:%t:%s|", p.ID, p.Enabled, p.Type)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:12])
}
