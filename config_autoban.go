package main

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/corazawaf/coraza-spoa/internal/autoban"
)

// yamlDuration parses Go duration strings such as 20ms, 60s, or 15m.
type yamlDuration struct {
	time.Duration
}

func (d *yamlDuration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	d.Duration = value
	return nil
}

type autobanYAML struct {
	Enabled                 bool         `yaml:"enabled"`
	Mode                    string       `yaml:"mode"`
	OnStoreError            string       `yaml:"on_store_error"`
	Redis                   redisYAML    `yaml:"redis"`
	OperationTimeout        yamlDuration `yaml:"operation_timeout"`
	RequestStoreBudget      yamlDuration `yaml:"request_store_budget"`
	MaxConcurrentOperations int          `yaml:"max_concurrent_operations"`
	AdminSocket             string       `yaml:"admin_socket"`
	GlobalPolicies          []policyYAML `yaml:"global_policies"`
}

type redisYAML struct {
	Addresses            []string `yaml:"addresses"`
	MasterName           string   `yaml:"master_name"`
	Username             string   `yaml:"username"`
	PasswordFile         string   `yaml:"password_file"`
	SentinelUsername     string   `yaml:"sentinel_username"`
	SentinelPasswordFile string   `yaml:"sentinel_password_file"`
	DB                   int      `yaml:"db"`
	KeyPrefix            string   `yaml:"key_prefix"`
	TLS                  tlsYAML  `yaml:"tls"`
}

type tlsYAML struct {
	Enabled    bool   `yaml:"enabled"`
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
}

type policyYAML struct {
	ID              string       `yaml:"id"`
	Enabled         bool         `yaml:"enabled"`
	Type            string       `yaml:"type"`
	RuleTags        []string     `yaml:"rule_tags"`
	RuleIDs         []int        `yaml:"rule_ids"`
	MinAnomalyScore *int64       `yaml:"min_anomaly_score"`
	Threshold       int          `yaml:"threshold"`
	Window          yamlDuration `yaml:"window"`
	BanFor          yamlDuration `yaml:"ban_for"`
	Methods         []string     `yaml:"methods"`
	PathExact       []string     `yaml:"path_exact"`
	PathPrefix      []string     `yaml:"path_prefix"`
	Requests        int64        `yaml:"requests"`
	Period          yamlDuration `yaml:"period"`
	Burst           int64        `yaml:"burst"`
}

type appAutobanYAML struct {
	Enabled     bool         `yaml:"enabled"`
	Mode        string       `yaml:"mode"`
	ExemptCIDRs []string     `yaml:"exempt_cidrs"`
	Policies    []policyYAML `yaml:"policies"`
}

// compileAutoban translates typed YAML into the immutable package config. It
// never opens a connection, listener, or key.
func compileAutoban(c *config) (autoban.Config, autoban.RedisConfig, error) {
	ab := c.Autoban
	input := autoban.ConfigInput{
		Enabled:                 ab.Enabled,
		Mode:                    autoban.Mode(ab.Mode),
		OnStoreError:            ab.OnStoreError,
		OperationTimeout:        ab.OperationTimeout.Duration,
		RequestStoreBudget:      ab.RequestStoreBudget.Duration,
		MaxConcurrentOperations: ab.MaxConcurrentOperations,
		Redis: autoban.RedisConfig{
			Addresses:            ab.Redis.Addresses,
			MasterName:           ab.Redis.MasterName,
			Username:             ab.Redis.Username,
			PasswordFile:         ab.Redis.PasswordFile,
			SentinelUsername:     ab.Redis.SentinelUsername,
			SentinelPasswordFile: ab.Redis.SentinelPasswordFile,
			DB:                   ab.Redis.DB,
			KeyPrefix:            ab.Redis.KeyPrefix,
			TLS: autoban.TLSConfig{
				Enabled:    ab.Redis.TLS.Enabled,
				CAFile:     ab.Redis.TLS.CAFile,
				CertFile:   ab.Redis.TLS.CertFile,
				KeyFile:    ab.Redis.TLS.KeyFile,
				ServerName: ab.Redis.TLS.ServerName,
			},
		},
	}
	for _, p := range ab.GlobalPolicies {
		input.GlobalPolicies = append(input.GlobalPolicies, toPolicyInput(p))
	}
	for _, app := range c.Applications {
		if !app.Autoban.Enabled {
			continue
		}
		entry := autoban.ApplicationInput{
			Name:        app.Name,
			Enabled:     app.Autoban.Enabled,
			Mode:        autoban.Mode(app.Autoban.Mode),
			ExemptCIDRs: app.Autoban.ExemptCIDRs,
		}
		for _, p := range app.Autoban.Policies {
			entry.Policies = append(entry.Policies, toPolicyInput(p))
		}
		input.Applications = append(input.Applications, entry)
	}

	compiled, err := autoban.Compile(input)
	if err != nil {
		return autoban.Config{}, autoban.RedisConfig{}, err
	}
	return compiled, compiled.RedisConfig(), nil
}

func toPolicyInput(p policyYAML) autoban.PolicyInput {
	return autoban.PolicyInput{
		ID:              p.ID,
		Enabled:         p.Enabled,
		Type:            p.Type,
		RuleTags:        p.RuleTags,
		RuleIDs:         p.RuleIDs,
		MinAnomalyScore: p.MinAnomalyScore,
		Threshold:       p.Threshold,
		Window:          p.Window.Duration,
		BanFor:          p.BanFor.Duration,
		Methods:         p.Methods,
		PathExact:       p.PathExact,
		PathPrefix:      p.PathPrefix,
		Requests:        p.Requests,
		Period:          p.Period.Duration,
		Burst:           p.Burst,
	}
}
