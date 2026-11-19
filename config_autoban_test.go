package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/corazawaf/coraza-spoa/internal/autoban"
)

const yamlTemplate = `bind: unix:///tmp/spoa.sock
autoban:
  enabled: {{ENABLED}}
  mode: {{MODE}}
  on_store_error: {{ONERROR}}
  redis:
    addresses: [{{ADDRS}}]
    master_name: {{MASTER}}
    password_file: {{PASSFILE}}
    key_prefix: {{PREFIX}}
  operation_timeout: {{OPTIMEOUT}}
  request_store_budget: {{BUDGET}}
  max_concurrent_operations: {{CONCURRENCY}}
  global_policies:
{{GLOBAL}}
applications:
  - name: {{APPNAME}}
    autoban:
      enabled: {{APPENABLED}}
      policies:
{{POLICIES}}
`

const defaultPolicies = `        - id: p1
          enabled: true
          type: match
          rule_ids: [100]
          window: 60s
          threshold: 3
          ban_for: 15m`

var defaultYAML = map[string]string{
	"ENABLED": "true", "MODE": "observe", "ONERROR": "continue_waf",
	"ADDRS": "127.0.0.1:6379", "MASTER": `""`, "PASSFILE": `""`, "PREFIX": "test",
	"OPTIMEOUT": "20ms", "BUDGET": "50ms", "CONCURRENCY": "128",
	"APPNAME": "app1", "APPENABLED": "true", "POLICIES": defaultPolicies,
	"GLOBAL": "    []",
}

func renderConfig(overrides map[string]string) string {
	values := make(map[string]string, len(defaultYAML))
	for k, v := range defaultYAML {
		values[k] = v
	}
	for k, v := range overrides {
		values[k] = v
	}
	raw := yamlTemplate
	for k, v := range values {
		raw = strings.ReplaceAll(raw, "{{"+k+"}}", v)
	}
	return raw
}

func decodeConfig(t *testing.T, raw string) (*config, error) {
	t.Helper()
	d := yaml.NewDecoder(strings.NewReader(raw))
	d.KnownFields(true)
	var c config
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func compileRaw(t *testing.T, raw string) (autoban.Config, autoban.RedisConfig, error) {
	t.Helper()
	c, err := decodeConfig(t, raw)
	if err != nil {
		return autoban.Config{}, autoban.RedisConfig{}, err
	}
	return compileAutoban(c)
}

func matchPolicy(window, threshold, banFor string) string {
	return fmt.Sprintf(`        - id: p1
          enabled: true
          type: match
          rule_ids: [100]
          window: %s
          threshold: %s
          ban_for: %s`, window, threshold, banFor)
}

func ratePolicy(requests, period, burst string) string {
	return fmt.Sprintf(`        - id: r1
          enabled: true
          type: rate
          methods: [POST]
          path_exact: [/login]
          requests: %s
          period: %s
          burst: %s`, requests, period, burst)
}

func TestAutobanConfig(t *testing.T) {
	t.Run("defaults disabled observe and timings", func(t *testing.T) {
		cfg, _, err := compileRaw(t, renderConfig(map[string]string{"ENABLED": "false", "APPENABLED": "false"}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Enabled() || cfg.Mode() != autoban.ModeObserve {
			t.Fatalf("expected disabled/observe, got %t/%s", cfg.Enabled(), cfg.Mode())
		}
		if cfg.OperationTimeout() != 20*time.Millisecond || cfg.RequestStoreBudget() != 50*time.Millisecond || cfg.MaxConcurrentOperations() != 128 {
			t.Fatalf("unexpected defaults: %s %s %d", cfg.OperationTimeout(), cfg.RequestStoreBudget(), cfg.MaxConcurrentOperations())
		}
	})

	t.Run("opt-in per app", func(t *testing.T) {
		cfg, _, err := compileRaw(t, renderConfig(nil))
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Enabled() {
			t.Fatal("expected enabled config")
		}
	})

	for name, prefix := range map[string]string{
		"glob": "*", "separator": "a/b", "space": "a b", "too-long": strings.Repeat("a", 65),
	} {
		t.Run("bad prefix "+name, func(t *testing.T) {
			if _, _, err := compileRaw(t, renderConfig(map[string]string{"PREFIX": prefix})); err == nil {
				t.Fatal("expected key_prefix rejection")
			}
		})
	}

	t.Run("bad policy id", func(t *testing.T) {
		policies := strings.Replace(defaultPolicies, "id: p1", "id: bad/id", 1)
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"POLICIES": policies})); err == nil {
			t.Fatal("expected policy id rejection")
		}
	})

	t.Run("participating app name restrictions", func(t *testing.T) {
		long := strings.Repeat("x", 257)
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"APPNAME": long})); err == nil {
			t.Fatal("expected long participating app name rejection")
		}
		// Legacy disabled applications keep their previous permissive rules.
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"APPNAME": long, "APPENABLED": "false"})); err != nil {
			t.Fatalf("legacy app name must not be restricted: %v", err)
		}
	})

	boundaries := []struct {
		name, field, value string
		wantErr            bool
	}{
		{"window below", "POLICIES", matchPolicy("29s", "3", "15m"), true},
		{"window min", "POLICIES", matchPolicy("30s", "3", "15m"), false},
		{"window max", "POLICIES", matchPolicy("1h", "3", "15m"), false},
		{"window above", "POLICIES", matchPolicy("1h1s", "3", "15m"), true},
		{"threshold below", "POLICIES", matchPolicy("60s", "0", "15m"), true},
		{"threshold min", "POLICIES", matchPolicy("60s", "1", "15m"), false},
		{"threshold max", "POLICIES", matchPolicy("60s", "256", "15m"), false},
		{"threshold above", "POLICIES", matchPolicy("60s", "257", "15m"), true},
		{"ban below", "POLICIES", matchPolicy("60s", "3", "29s"), true},
		{"ban min", "POLICIES", matchPolicy("60s", "3", "30s"), false},
		{"ban max", "POLICIES", matchPolicy("60s", "3", "24h"), false},
		{"ban above", "POLICIES", matchPolicy("60s", "3", "24h1s"), true},
	}
	for _, tc := range boundaries {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := compileRaw(t, renderConfig(map[string]string{tc.field: tc.value}))
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}

	rateBoundaries := []struct {
		name, value string
		wantErr     bool
	}{
		{"period min", ratePolicy("10", "1ms", "10"), false},
		{"period max", ratePolicy("20", "1h", "10"), false},
		{"period above", ratePolicy("20", "1h1ms", "10"), true},
		{"period fractional", ratePolicy("20", "1500us", "10"), true},
		{"burst zero", ratePolicy("20", "10s", "0"), true},
		{"burst above", ratePolicy("20", "10s", "10001"), true},
		{"refill too high", ratePolicy("10001", "1s", "10"), true},
	}
	for _, tc := range rateBoundaries {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := compileRaw(t, renderConfig(map[string]string{"POLICIES": tc.value}))
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}

	t.Run("only enabled global policies", func(t *testing.T) {
		global := `    - id: g1
      enabled: false
      type: match
      rule_ids: [200]
      window: 60s
      threshold: 1
      ban_for: 15m`
		cfg, _, err := compileRaw(t, renderConfig(map[string]string{"GLOBAL": global}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.GlobalPolicyCount() != 0 {
			t.Fatalf("disabled global policy must be skipped, got %d", cfg.GlobalPolicyCount())
		}
	})

	t.Run("invalid cidr", func(t *testing.T) {
		raw := strings.Replace(renderConfig(nil), "      enabled: true\n      policies:", "      enabled: true\n      exempt_cidrs: [not-a-cidr]\n      policies:", 1)
		if _, _, err := compileRaw(t, raw); err == nil {
			t.Fatal("expected invalid CIDR rejection")
		}
	})

	t.Run("unknown fields", func(t *testing.T) {
		raw := renderConfig(nil) + "bogus: true\n"
		if _, err := decodeConfig(t, raw); err == nil {
			t.Fatal("expected unknown field rejection")
		}
	})

	t.Run("tls verification field rejected", func(t *testing.T) {
		raw := strings.Replace(renderConfig(nil), "    key_prefix: test", "    key_prefix: test\n    insecure_skip_verify: true", 1)
		if _, err := decodeConfig(t, raw); err == nil {
			t.Fatal("TLS verification must not be disableable")
		}
	})

	t.Run("mixed policy fields", func(t *testing.T) {
		policies := strings.Replace(defaultPolicies, "          rule_ids: [100]", "          rule_ids: [100]\n          requests: 20", 1)
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"POLICIES": policies})); err == nil {
			t.Fatal("expected mixed policy-type field rejection")
		}
	})

	t.Run("empty match selectors", func(t *testing.T) {
		policies := strings.Replace(defaultPolicies, "          rule_ids: [100]\n", "", 1)
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"POLICIES": policies})); err == nil {
			t.Fatal("expected empty selector rejection")
		}
	})

	t.Run("unsupported failure mode", func(t *testing.T) {
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"ONERROR": "fail_closed"})); err == nil {
			t.Fatal("expected unsupported failure mode rejection")
		}
	})

	t.Run("policy overflow", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 33; i++ {
			fmt.Fprintf(&b, "        - id: p%d\n          enabled: true\n          type: match\n          rule_ids: [100]\n          window: 60s\n          threshold: 1\n          ban_for: 15m\n", i)
		}
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"POLICIES": strings.TrimRight(b.String(), "\n")})); err == nil {
			t.Fatal("expected overflow rejection")
		}
	})

	t.Run("spec example rule compiles", func(t *testing.T) {
		c, err := decodeConfig(t, renderConfig(nil))
		if err != nil {
			t.Fatal(err)
		}
		c.Applications[0].Log.Format = "json"
		c.Applications[0].Directives = `Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRule REQUEST_FILENAME "@rx ^/(?:\.env|\.git/config)$" "id:190100,phase:1,pass,nolog,t:none,tag:'autoban/secret-probe',msg:'Secret file probe'"
SecRuleEngine On`
		if _, err := c.newApplications(); err != nil {
			t.Fatalf("spec example rule failed to compile: %v", err)
		}
	})
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAutobanSecretsAndTLS(t *testing.T) {
	t.Run("disabled never reads secret", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		raw := renderConfig(map[string]string{
			"ENABLED": "false", "APPENABLED": "false",
			"PASSFILE": missing,
		})
		if _, rcfg, err := compileRaw(t, raw); err != nil {
			t.Fatalf("disabled mode must not read secrets: %v", err)
		} else if rcfg.Password != "" {
			t.Fatal("disabled mode resolved a password")
		}
	})

	t.Run("enabled unreadable secret fails", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		raw := renderConfig(map[string]string{"PASSFILE": missing})
		if _, _, err := compileRaw(t, raw); err == nil {
			t.Fatal("expected unreadable secret failure")
		}
	})

	t.Run("trim one trailing newline", func(t *testing.T) {
		path := writeSecret(t, "s3cr3t\n")
		raw := renderConfig(map[string]string{"PASSFILE": path})
		_, rcfg, err := compileRaw(t, raw)
		if err != nil {
			t.Fatal(err)
		}
		if rcfg.Password != "s3cr3t" {
			t.Fatalf("password = %q", rcfg.Password)
		}
	})

	t.Run("embedded NUL rejected", func(t *testing.T) {
		path := writeSecret(t, "a\x00b")
		raw := renderConfig(map[string]string{"PASSFILE": path})
		if _, _, err := compileRaw(t, raw); err == nil {
			t.Fatal("expected NUL rejection")
		}
	})

	t.Run("incomplete tls pair", func(t *testing.T) {
		raw := renderConfig(map[string]string{}) + "bogus: true\n"
		if _, err := decodeConfig(t, raw); err == nil {
			t.Fatal("unexpected decode success")
		}
		c, err := decodeConfig(t, renderConfig(map[string]string{}))
		if err != nil {
			t.Fatal(err)
		}
		c.Autoban.Redis.TLS.Enabled = true
		c.Autoban.Redis.TLS.CertFile = "/tmp/cert.pem"
		if _, _, err := compileAutoban(c); err == nil {
			t.Fatal("expected incomplete TLS pair rejection")
		}
	})

	t.Run("standalone requires one address", func(t *testing.T) {
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"ADDRS": ""})); err == nil {
			t.Fatal("empty standalone address list must fail")
		}
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"ADDRS": "a:6379,b:6379"})); err == nil {
			t.Fatal("standalone must reject multiple addresses")
		}
	})

	t.Run("sentinel requires master and address", func(t *testing.T) {
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"MASTER": "mymaster"})); err != nil {
			t.Fatalf("sentinel with defaults should pass: %v", err)
		}
		if _, _, err := compileRaw(t, renderConfig(map[string]string{"MASTER": "mymaster", "ADDRS": ""})); err == nil {
			t.Fatal("sentinel without address must fail")
		}
	})
}
