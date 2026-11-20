package autoban

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisCmdRunner is the narrow command surface the adapter uses. Keeping it
// small lets unit tests inject a deterministic fake without faking Redis Lua.
type redisCmdRunner interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	EvalSha(ctx context.Context, sha1 string, keys []string, args ...interface{}) *redis.Cmd
	ScriptLoad(ctx context.Context, script string) *redis.StringCmd
	Time(ctx context.Context) *redis.TimeCmd
	Close() error
}

// RedisStore owns one shared primary connection pool for a runtime.
type RedisStore struct {
	config RedisConfig
	client redisCmdRunner
	sem    chan struct{}
}

// NewRedisStore validates local settings and builds the shared pool. An
// unreachable Redis is not a constructor error: startup continues degraded.
func NewRedisStore(config RedisConfig) (*RedisStore, error) {
	if config.KeyPrefix == "" {
		return nil, fmt.Errorf("autoban: empty key prefix")
	}
	if config.OperationTimeout <= 0 || config.RequestStoreBudget < config.OperationTimeout {
		return nil, fmt.Errorf("autoban: invalid store timings")
	}
	if config.MaxConcurrentOperations <= 0 {
		return nil, fmt.Errorf("autoban: invalid concurrency limit")
	}
	if config.MasterName == "" && len(config.Addresses) != 1 {
		return nil, fmt.Errorf("autoban: standalone Redis requires exactly one address")
	}
	if config.MasterName != "" && len(config.Addresses) == 0 {
		return nil, fmt.Errorf("autoban: Sentinel requires at least one address")
	}

	tlsConfig, err := buildTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}

	var client redisCmdRunner
	if config.MasterName != "" {
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       config.MasterName,
			SentinelAddrs:    config.Addresses,
			SentinelUsername: config.SentinelUsername,
			SentinelPassword: config.SentinelPassword,
			Username:         config.Username,
			Password:         config.Password,
			DB:               config.DB,
			TLSConfig:        tlsConfig,
			MaxRetries:       -1,
		})
	} else {
		client = redis.NewClient(&redis.Options{
			Addr:       config.Addresses[0],
			Username:   config.Username,
			Password:   config.Password,
			DB:         config.DB,
			TLSConfig:  tlsConfig,
			MaxRetries: -1,
		})
	}
	return newRedisStoreWithClient(config, client), nil
}

func newRedisStoreWithClient(config RedisConfig, client redisCmdRunner) *RedisStore {
	return &RedisStore{
		config: config,
		client: client,
		sem:    make(chan struct{}, config.MaxConcurrentOperations),
	}
}

// buildTLSConfig always verifies the server. Verification cannot be disabled.
func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("autoban: CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("autoban: CA file contains no certificates")
		}
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		ServerName:         cfg.ServerName,
		RootCAs:            roots,
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("autoban: TLS certificate pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// Close releases the shared pool. It is called once at bounded shutdown.
func (s *RedisStore) Close() error { return s.client.Close() }

// budget tracks the monotonic dependency time consumed within one request.
type budget struct {
	remaining time.Duration
}

func newBudget(total time.Duration) *budget { return &budget{remaining: total} }

func (b *budget) slice(parent context.Context, opTimeout time.Duration) (context.Context, context.CancelFunc) {
	return operationDeadline(parent, opTimeout, b.remaining)
}

func (b *budget) consume(start time.Time) {
	b.remaining = remainingAfter(b.remaining, time.Since(start))
}

func remainingAfter(remaining, elapsed time.Duration) time.Duration {
	r := remaining - elapsed
	if r < 0 {
		return 0
	}
	return r
}

// operationDeadline uses the minimum of the operation timeout, the remaining
// request budget, and the parent deadline.
func operationDeadline(parent context.Context, opTimeout, remaining time.Duration) (context.Context, context.CancelFunc) {
	limit := opTimeout
	if remaining < limit {
		limit = remaining
	}
	if limit <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	return context.WithTimeout(parent, limit)
}

// acquire rejects excess local work immediately instead of queueing.
func (s *RedisStore) acquire(_ context.Context) error {
	select {
	case s.sem <- struct{}{}:
		return nil
	default:
		return &StoreError{Reason: ReasonSaturated}
	}
}

func (s *RedisStore) release() { <-s.sem }

func scriptHash(script string) string {
	sum := sha1.Sum([]byte(script))
	return hex.EncodeToString(sum[:])
}

// eval performs exactly one script attempt. An ambiguous timeout is reported
// as uncertain and is never replayed.
func (s *RedisStore) eval(ctx context.Context, script string, keys []string, args []interface{}, mutation bool) (interface{}, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	opCtx, cancel := operationDeadline(ctx, s.config.OperationTimeout, s.config.RequestStoreBudget)
	defer cancel()
	cmd := s.client.Eval(opCtx, script, keys, args...)
	if err := cmd.Err(); err != nil {
		return nil, classifyRedisError(err, mutation)
	}
	return cmd.Result()
}

// evalWithScript recovers from an explicit NOSCRIPT within the original
// operation deadline. A missing script was not executed, so this is safe.
func (s *RedisStore) evalWithScript(ctx context.Context, script string, keys []string, args []interface{}) (interface{}, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	opCtx, cancel := operationDeadline(ctx, s.config.OperationTimeout, s.config.RequestStoreBudget)
	defer cancel()
	hash := scriptHash(script)
	cmd := s.client.EvalSha(opCtx, hash, keys, args...)
	if cmd.Err() != nil && strings.Contains(strings.ToUpper(cmd.Err().Error()), "NOSCRIPT") {
		if _, err := s.client.ScriptLoad(opCtx, script).Result(); err != nil {
			return nil, classifyRedisError(err, false)
		}
		cmd = s.client.EvalSha(opCtx, hash, keys, args...)
	}
	if err := cmd.Err(); err != nil {
		return nil, classifyRedisError(err, true)
	}
	return cmd.Result()
}

func classifyRedisError(err error, mutation bool) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	reason := ReasonConnection
	uncertain := false
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		reason, uncertain = ReasonTimeout, true
	case strings.Contains(msg, "readonly") || strings.Contains(msg, "read-only"):
		reason = ReasonReadOnly
	case strings.Contains(msg, "oom"):
		reason = ReasonOOM
	case strings.Contains(msg, "wrongtype"):
		reason = ReasonWrongType
	case strings.Contains(msg, "can't parse") || strings.Contains(msg, "malformed") || strings.Contains(msg, "noscript"):
		reason = ReasonMalformedReply
	}
	return &StoreError{Reason: reason, Uncertain: uncertain && mutation, Err: err}
}

// Store implementation: every accessed key is explicit in the script call.
func (s *RedisStore) Begin(ctx context.Context, cmd BeginCommand) (BeginResult, error) {
	keys := []string{
		stateKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeGlobal, "", cmd.Subject.IP),
		stateKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeApplication, cmd.Subject.Application, cmd.Subject.IP),
		fenceKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeGlobal, "", cmd.Subject.IP),
		fenceKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeApplication, cmd.Subject.Application, cmd.Subject.IP),
	}
	args := []interface{}{
		string(cmd.Subject.Mode), cmd.Subject.Application, ipHex(cmd.Subject.IP),
		s.config.KeyPrefix + "-revision", requestIDHex(cmd.RequestID), len(cmd.Rates),
	}
	for _, r := range cmd.Rates {
		args = append(args, r.Ref.Fingerprint, r.Requests, r.PeriodMS, r.Burst)
	}
	res, err := s.evalWithScript(ctx, beginScript, keys, args)
	if err != nil {
		return BeginResult{}, err
	}
	result, err := parseBeginResult(res)
	fillBanSubject(result.Bans, cmd.Subject)
	return result, err
}

func fillBanSubject(bans []BanRecord, subject Subject) {
	for i := range bans {
		bans[i].Subject = subject
	}
}

func (s *RedisStore) Observe(ctx context.Context, cmd ObserveCommand) (ObserveResult, error) {
	keys := []string{
		stateKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeGlobal, "", cmd.Subject.IP),
		stateKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeApplication, cmd.Subject.Application, cmd.Subject.IP),
		fenceKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeGlobal, "", cmd.Subject.IP),
		fenceKey(s.config.KeyPrefix, cmd.Subject.Mode, ScopeApplication, cmd.Subject.Application, cmd.Subject.IP),
	}
	args := []interface{}{
		string(cmd.Subject.Mode), cmd.Subject.Application, ipHex(cmd.Subject.IP),
		requestIDHex(cmd.RequestID), cmd.Revision, cmd.AdmittedAtMS,
		nonceFor(cmd.Fences, ScopeGlobal), nonceFor(cmd.Fences, ScopeApplication),
		len(cmd.SuppressedUntilMS),
	}
	for _, scope := range []Scope{ScopeGlobal, ScopeApplication} {
		if until, ok := cmd.SuppressedUntilMS[scope]; ok {
			args = append(args, string(scope), until)
		}
	}
	args = append(args, len(cmd.Policies))
	for _, p := range cmd.Policies {
		args = append(args, p.Ref.Fingerprint, p.Ref.ID, string(p.Ref.Scope), p.Threshold, p.WindowMS, p.BanForMS)
	}
	res, err := s.evalWithScript(ctx, observeScript, keys, args)
	if err != nil {
		return ObserveResult{}, err
	}
	result, err := parseObserveResult(res)
	fillBanSubject(result.Bans, cmd.Subject)
	return result, err
}

func (s *RedisStore) Unban(ctx context.Context, req UnbanRequest) (UnbanResult, error) {
	state := stateKey(s.config.KeyPrefix, req.Mode, req.Scope, req.Application, req.IP)
	fence := fenceKey(s.config.KeyPrefix, req.Mode, req.Scope, req.Application, req.IP)
	receipt := adminKey(s.config.KeyPrefix, req.Mode, req.IP, adminScopeID(req.Scope, req.Application), req.OperationID)
	other := stateKey(s.config.KeyPrefix, req.Mode, ScopeGlobal, "", req.IP)
	nonce, err := randomNonce()
	if err != nil {
		return UnbanResult{}, &StoreError{Reason: ReasonEntropyFailure, Err: err}
	}
	digest := adminDigest(req)
	args := []interface{}{
		string(req.Scope), req.OperationID, digest, nonce,
		req.SuppressFor.Milliseconds(),
	}
	res, err := s.evalWithScript(ctx, unbanScript, []string{state, fence, receipt, other}, args)
	if err != nil {
		return UnbanResult{}, err
	}
	result, err := parseUnbanResult(res)
	if result.OtherBan != nil {
		result.OtherBan.Subject = Subject{Application: req.Application, IP: req.IP, Mode: req.Mode}
	}
	return result, err
}

func (s *RedisStore) Inspect(ctx context.Context, req InspectRequest) (InspectResult, error) {
	keys := []string{
		stateKey(s.config.KeyPrefix, req.Subject.Mode, ScopeGlobal, "", req.Subject.IP),
		stateKey(s.config.KeyPrefix, req.Subject.Mode, ScopeApplication, req.Subject.Application, req.Subject.IP),
		fenceKey(s.config.KeyPrefix, req.Subject.Mode, ScopeGlobal, "", req.Subject.IP),
		fenceKey(s.config.KeyPrefix, req.Subject.Mode, ScopeApplication, req.Subject.Application, req.Subject.IP),
	}
	res, err := s.evalWithScript(ctx, inspectScript, keys, []interface{}{string(req.Subject.Mode)})
	if err != nil {
		return InspectResult{}, err
	}
	result, err := parseInspectResult(res)
	fillBanSubject(result.Bans, req.Subject)
	return result, err
}

func (s *RedisStore) List(ctx context.Context, req ListRequest) (ListResult, error) {
	pattern := fmt.Sprintf("%s:v1:%s:{*}:state", s.config.KeyPrefix, req.Mode)
	if req.Scope == ScopeApplication {
		pattern += ":app:" + encodeApp(req.Application)
	} else {
		pattern += ":global"
	}
	res, err := s.eval(ctx, listScript, nil, []interface{}{pattern, req.Cursor, req.Limit}, false)
	if err != nil {
		return ListResult{}, err
	}
	return parseListResult(res)
}

func nonceFor(m map[Scope]string, scope Scope) string {
	if m == nil {
		return "none"
	}
	if nonce, ok := m[scope]; ok && nonce != "" {
		return nonce
	}
	return "none"
}

func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func adminDigest(req UnbanRequest) string {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s",
		req.Mode, req.Scope, req.Application, ipHex(req.IP), req.OperationID,
		req.SuppressFor.Milliseconds(), req.Reason, adminScopeID(req.Scope, req.Application))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
