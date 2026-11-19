package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/corazawaf/coraza-spoa/internal/autoban"
)

// autobanRuntime owns the one shared store and the currently published engine.
// Policy reloads replace the engine but keep the store and active admissions.
type autobanRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc

	config      autoban.Config
	redisConfig autoban.RedisConfig
	store       *autoban.RedisStore

	mu     sync.RWMutex
	engine *autoban.Engine

	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	adminMu       sync.Mutex
	adminServer   *http.Server
	adminListener net.Listener
}

// newAutobanRuntime initializes dependencies after validation-only mode exits.
// A disabled feature has no runtime, connection, or listener.
func newAutobanRuntime(ctx context.Context, compiled autoban.Config, redisConfig autoban.RedisConfig) (*autobanRuntime, error) {
	if !compiled.Enabled() {
		return nil, nil
	}
	store, err := autoban.NewRedisStore(redisConfig)
	if err != nil {
		return nil, fmt.Errorf("initializing autoban store: %w", err)
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	r := &autobanRuntime{
		ctx: runtimeCtx, cancel: cancel,
		config: compiled, redisConfig: redisConfig, store: store,
	}
	engine, err := autoban.NewEngine(compiled, store)
	if err != nil {
		cancel()
		store.Close()
		return nil, err
	}
	r.engine = engine
	autoban.SetConfigRevision(compiled.Revision())
	return r, nil
}

// Engine returns the currently published engine. It is captured by each
// application at publication time, so in-flight requests keep their snapshot.
func (r *autobanRuntime) Engine() *autoban.Engine {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.engine
}

// ReplaceConfig validates a replacement policy snapshot before publishing it.
// Restart-only settings must be rejected before this method is called.
func (r *autobanRuntime) ReplaceConfig(compiled autoban.Config) error {
	if r == nil {
		return fmt.Errorf("autoban runtime is not active")
	}
	if !compiled.Enabled() {
		return fmt.Errorf("disabling autoban requires a restart")
	}
	if !sameRestartSettings(r.config, compiled, r.redisConfig, compiled.RedisConfig()) {
		return fmt.Errorf("changing autoban store settings requires a restart")
	}
	engine, err := autoban.NewEngine(compiled, r.store)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = compiled
	r.engine = engine
	r.mu.Unlock()
	autoban.SetConfigRevision(compiled.Revision())
	return nil
}

func sameRestartSettings(oldCfg, newCfg autoban.Config, oldRedis, newRedis autoban.RedisConfig) bool {
	return oldCfg.Enabled() == newCfg.Enabled() &&
		oldCfg.OperationTimeout() == newCfg.OperationTimeout() &&
		oldCfg.RequestStoreBudget() == newCfg.RequestStoreBudget() &&
		oldCfg.MaxConcurrentOperations() == newCfg.MaxConcurrentOperations() &&
		reflect.DeepEqual(oldRedis, newRedis)
}

// StartAdmin binds the admin API to the configured Unix socket only.
func (r *autobanRuntime) StartAdmin(path string) error {
	if r == nil || !r.config.Enabled() {
		return nil
	}
	handler := autoban.NewAdminHandler(r.store, func() autoban.Config {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.config
	})
	server, listener, err := autoban.NewAdminSocket(path, handler)
	if err != nil {
		return err
	}
	r.adminMu.Lock()
	r.adminServer, r.adminListener = server, listener
	r.adminMu.Unlock()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			// A socket failure degrades administration only; SPOA stays live.
			return
		}
	}()
	return nil
}

// Track marks a policy operation as active for bounded shutdown.
func (r *autobanRuntime) Track() func() {
	if r == nil {
		return func() {}
	}
	r.wg.Add(1)
	var once sync.Once
	return func() { once.Do(r.wg.Done) }
}

// Shutdown cancels active policy calls, waits within their budgets, and closes
// the shared pool exactly once.
func (r *autobanRuntime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.cancel()
	r.adminMu.Lock()
	if r.adminServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = r.adminServer.Shutdown(shutdownCtx)
		cancel()
	}
	r.adminMu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	r.closeOnce.Do(func() {
		r.closeErr = r.store.Close()
	})
	return r.closeErr
}
