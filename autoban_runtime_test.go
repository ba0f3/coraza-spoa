package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/corazawaf/coraza-spoa/internal/autoban"
)

func runtimeConfig(t *testing.T, threshold int, mode autoban.Mode, passwordFile string) (autoban.Config, autoban.RedisConfig) {
	t.Helper()
	cfg, err := autoban.Compile(autoban.ConfigInput{
		Enabled: true, Mode: mode,
		Redis: autoban.RedisConfig{
			Addresses: []string{"127.0.0.1:1"}, KeyPrefix: "runtime-test",
			PasswordFile:     passwordFile,
			OperationTimeout: 20 * time.Millisecond, RequestStoreBudget: 50 * time.Millisecond,
			MaxConcurrentOperations: 128,
		},
		Applications: []autoban.ApplicationInput{{
			Name: "app1", Enabled: true,
			Policies: []autoban.PolicyInput{{
				ID: "p1", Enabled: true, Type: "match", RuleIDs: []int{190100},
				Threshold: threshold, Window: time.Minute, BanFor: time.Minute,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, cfg.RedisConfig()
}

func TestAutobanValidateOffline(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Compilation reads required secrets but never contacts Redis.
	_, redisConfig := runtimeConfig(t, 3, autoban.ModeObserve, secret)
	if redisConfig.Password != "password" {
		t.Fatalf("enabled validation must read the secret")
	}
	// A disabled config never reads secrets, even when the path is absent.
	disabled, err := autoban.Compile(autoban.ConfigInput{
		Redis: autoban.RedisConfig{Addresses: []string{"127.0.0.1:1"}, PasswordFile: filepath.Join(t.TempDir(), "missing")},
	})
	if err != nil {
		t.Fatalf("disabled mode must not read secrets: %v", err)
	}
	if disabled.Enabled() {
		t.Fatal("expected disabled config")
	}
}

func TestAutobanStartupUnavailable(t *testing.T) {
	compiled, redis := runtimeConfig(t, 3, autoban.ModeObserve, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime, err := newAutobanRuntime(ctx, compiled, redis)
	if err != nil {
		t.Fatalf("unreachable Redis must not block startup: %v", err)
	}
	if runtime == nil || runtime.Engine() == nil {
		t.Fatal("expected an engine sharing the store")
	}
	shutdownCtx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := runtime.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

func TestAutobanReloadSnapshot(t *testing.T) {
	compiled, redis := runtimeConfig(t, 3, autoban.ModeObserve, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime, err := newAutobanRuntime(ctx, compiled, redis)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Shutdown(context.Background())
	first := runtime.Engine()

	replacement, _ := runtimeConfig(t, 5, autoban.ModeEnforce, "")
	if err := runtime.ReplaceConfig(replacement); err != nil {
		t.Fatalf("policy-only replacement must succeed: %v", err)
	}
	if runtime.Engine() == first {
		t.Fatal("a new engine must be published")
	}

	// Restart-only replacement fails and retains the previously published engine.
	published := runtime.Engine()
	topologyChanged, err := autoban.Compile(autoban.ConfigInput{
		Enabled: true, Mode: autoban.ModeObserve,
		Redis: autoban.RedisConfig{
			Addresses: []string{"127.0.0.1:1"}, KeyPrefix: "different-prefix",
			OperationTimeout: 20 * time.Millisecond, RequestStoreBudget: 50 * time.Millisecond,
			MaxConcurrentOperations: 128,
		},
		Applications: []autoban.ApplicationInput{{Name: "app1", Enabled: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sameRestartSettings(compiled, topologyChanged, redis, topologyChanged.RedisConfig()) {
		t.Fatal("prefix change must be detected as restart-only")
	}
	if err := runtime.ReplaceConfig(topologyChanged); err == nil {
		t.Fatal("restart-only change must be rejected")
	}
	if runtime.Engine() != published {
		t.Fatal("rejected reload must not replace the published engine")
	}
}

func TestAutobanShutdown(t *testing.T) {
	compiled, redis := runtimeConfig(t, 3, autoban.ModeObserve, "")
	ctx, cancel := context.WithCancel(context.Background())
	runtime, err := newAutobanRuntime(ctx, compiled, redis)
	if err != nil {
		t.Fatal(err)
	}
	done := runtime.Track()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer stop()
		shutdownDone <- runtime.Shutdown(shutdownCtx)
	}()
	if ctx.Err() == nil {
		// Give the shutdown goroutine a chance to cancel the runtime context.
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.ctx.Err() == nil {
		t.Fatal("shutdown must cancel active policy calls")
	}
	done()
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
	cancel()
}
