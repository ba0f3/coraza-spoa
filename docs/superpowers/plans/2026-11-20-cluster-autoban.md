# Cluster-wide Scanner Auto-ban Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add shared scanner bans and endpoint rate limits to Coraza SPOA, with correct request ownership, bounded Redis work, and an auditable operator interface.

**Architecture:** `internal/autoban` owns immutable policy inputs, decisions, and Redis state. The existing request handler supplies trusted identity and owned request-phase evidence; HAProxy enforces separate policy variables. A process-owned Redis pool survives policy reloads, while each admitted request retains its policy snapshot.

**Tech Stack:** Go 1.25.7; existing Coraza/CRS, HAProxy SPOE, Prometheus and zerolog integrations; `github.com/redis/go-redis/v9`; Redis Lua; Docker Compose integration fixtures.

**Spec:** [Cluster-wide scanner auto-ban design](../specs/2026-11-20-cluster-autoban-design.md). Read it with this plan; its normative behavior takes precedence.

## Global Constraints

- Preserve module `github.com/corazawaf/coraza-spoa`, Go `1.25.7`, Coraza `v3.8.1`, CRS `v4.25.0`, and `haproxy-go v0.1.1`; no nested module or Coraza-core changes.
- Redis `7.2` or newer; standalone or Sentinel with primary reads/writes; no native Redis Cluster. Pin the resolved `go-redis/v9` version during implementation.
- `key_prefix`, policy IDs, and admin operation IDs use 1–64 characters from `[A-Za-z0-9._-]`; choose a prefix unique to the intended environment/policy cluster.
- Absent/disabled auto-ban performs no Redis connection or secret-file access. Enabled mode defaults to `observe`; the only store-failure behavior is `continue_waf`.
- Store defaults: operation `20 ms`, request store budget `50 ms`, concurrency `128`. Validate operation `1–100 ms`, budget at least operation timeout and at most `200 ms`, and positive concurrency with immediate saturation rejection.
- Subtract actual monotonic dependency time from one request store budget; exclude WAF time. Each operation also respects the parent deadline. Admission age is at most `30 s` by Redis and local monotonic clocks.
- Match window `30 s–1 h`, threshold `1–256`, ban `30 s–24 h`; at most `32` evaluated policies, `64` retained policy fields, and `256` selected rule records. Encoded field maximum `64 KiB`; subject hash maximum `4 MiB`.
- Rates require positive integer requests, period `1 ms–1 h` in whole milliseconds, at most `10,000` requests/second, burst `1–10,000`, and idle retention at least `30 s`; arithmetic must fit exact Redis Lua integers.
- Fence retention is at least `120 s`; unban suppression defaults to `60 s`, accepts `0–24 h`, and extends fence retention to at least suppression plus `30 s`. Admin receipts last `120 s` without refresh.
- One request-group invocation, one `Begin`, at most one aggregated `Observe`; no ambiguous command replay, background evidence queue, policy cache, or cross-delivery exactly-once claim. Explicit `NOSCRIPT` recovery shares the original operation deadline.
- Count only phases `1` and `2`; preserve WAF action/error semantics, detect-only behavior, and existing response correlation. Close or transfer each created transaction exactly once.
- Admin uses a Unix socket only, default `/run/coraza-spoa/autoban-admin.sock`, mode `0600`; bodies at most `8 KiB`; listing limit `1–100`, at most `1,000` application-inspected keys and a `100 ms` client deadline. At most `32` cursors retain up to `1,000` pending keys each for `120 s`; Redis SCAN internal work is not bounded by COUNT.
- Top-level enable, Redis connection/secret/TLS/prefix/DB, store timing/concurrency, and admin socket changes require restart. Per-application enable/mode, top-level mode, policies, and exemptions can reload.

## Review Focus

1. Unknown incoming app text must resolve to the configured default before namespacing or metrics; mapped IPv4 must share its IPv4 subject — Task 5, `TestAutobanResolvedIdentity`.
2. Encoded path aliases must retain HAProxy's raw-path semantics, without accidental decoding or unbounded URI keys — Task 1, `TestEngineRawPathSelectors`; Task 9, `TestClusterEncodedPaths`.
3. One exhausted bucket must prevent consumption from every overlapping bucket; shadow rejection must suppress all match evidence — Tasks 1/4, `TestEngineShadowStopsEvidence`, `TestRedisRateAllOrNothing`.
4. A ban shorter than its strike window, an expired unban fence, or a new first strike must not resurrect counters or invalidate age-valid concurrent admissions — Task 4, `TestRedisFreshWindows`, `TestRedisFenceABA`, `TestRedisConcurrentFirstStrike`.
5. Request detect-only plus response checking must still close a locally policy-denied transaction exactly once and retain an allowed one — Task 5, `TestAutobanTransactionOwnership`; Task 9, `TestClusterResponseOwnership`.

---

## Repository Map and Command Baseline

Paths below are relative to the actual repository root, not the documentation workspace's `source/` reference copies. Existing seams are `config.go`, `main.go`, `internal/application.go`, `internal/agent.go`, `internal/metrics.go`, and `internal/e2e_test.go`. Keep `internal/ttlcache.go` as the response-correlation owner.

New responsibilities: `internal/autoban/{types,engine,policy}.go` for contracts/selection; `{config,redis,keys,scripts}.go` and `lua/` for validation/store; `{admin,admin_socket,metrics,audit}.go` for operations; `internal/autoban_bridge.go` for Coraza/SPOE adaptation; root `autoban_runtime.go` for lifetime; `integration/autoban/` for real cluster tests.

**Existing commands:** `go test -race ./...`; `go test -race -v -tags=e2e ./internal` (requires `haproxy`); `go run mage.go build`; `FTW_HAPROXY_VERSION=2.8 go run mage.go ftw` (Docker required), repeated with `3.0` and `3.2`. Keep auto-ban disabled in FTW fixtures. Use `gofmt` on changed Go files and `go mod tidy` when dependencies change. Do not invoke `go run mage.go format` unconditionally: it calls `go work sync`, and this baseline has no `go.work`.

**Future commands:** `-tags=integration` tests, `integration/autoban/compose.yaml`, and `integration/autoban/run.sh` do not exist yet; Tasks 3 and 9 create them. An explicitly requested fixture must fail, not skip, when unavailable. No implementation tests or performance measurements were executed while writing this plan.

### Task 1: Fix the package contracts and pure engine behavior

**Files:** Create `internal/autoban/types.go`, `engine.go`, `policy.go`, and `engine_test.go`.

**Interfaces:** Produce the following exact APIs before dependent work starts. `Config` is a deeply copied, immutable compiled snapshot; its revision, enabled applications, effective modes, exemptions, selectors, policy fingerprints, and store limits are private implementation data.

```go
func NewEngine(config Config, store Store) (*Engine, error)
func (e *Engine) Begin(ctx context.Context, meta RequestMeta) (Admission, Decision)
func (e *Engine) Observe(ctx context.Context, admission Admission, evidence Evidence) Decision
type Store interface {
	Begin(context.Context, BeginCommand) (BeginResult, error)
	Observe(context.Context, ObserveCommand) (ObserveResult, error)
	Unban(context.Context, UnbanRequest) (UnbanResult, error)
	Inspect(context.Context, InspectRequest) (InspectResult, error)
	List(context.Context, ListRequest) (ListResult, error)
}
```

Define these shared structures in `types.go`; durations passed to Lua are integer milliseconds. Map keys use `Scope`, whose values are `application` and `global`; `Mode` is `observe`/`enforce`; `Action` is `none`/`ban`/`throttle`; `RequestID` is `[16]byte`.

| Type | Fields and contract |
| --- | --- |
| `Subject` | `Application string`, `IP netip.Addr`, `Mode Mode`; canonical configured app and `IP.Unmap()` only. |
| `RequestMeta` | `Subject Subject`, `RequestID RequestID`, `Method string`, `RawPath string`; copied request metadata remains outside Store commands. |
| `PolicyRef` | `ID string`, `Fingerprint string`, `Scope Scope`; fingerprint is SHA-256 of canonical semantics including configured ID; a global fingerprint excludes the originating application. |
| `MatchSpec`, `RateSpec` | Match: `Ref PolicyRef`, `Threshold int`, `WindowMS, BanForMS int64`; rate: `Ref PolicyRef`, `Requests, PeriodMS, Burst int64`. Only selected policy parameters reach the store. |
| `Admission` | Private captured `Config`; `Meta RequestMeta`, `RedisAdmittedAtMS int64`, `LocalAdmittedAt time.Time`, `Fences map[Scope]string`, `RemainingStoreBudget time.Duration`, `Usable, ShadowStopped bool`. |
| `RuleMatch`, `Evidence` | Match: `ID, Phase int`, `Tags []string`, `Severity string`; evidence: `Matches []RuleMatch`, `AnomalyScore *int64`, `WAFInterrupted, InspectionError bool`; copy all retained slices. |
| `BanRecord` | `Subject Subject`, `Ref PolicyRef`, `Revision string`, `QualifyingPolicyIDs []string`, `TriggerRequestID RequestID`, `Count int`, `WindowMS, CreatedAtMS, ExpiresAtMS int64`. |
| `Decision` | `Action, WouldAction Action`, `Scope Scope`, `PolicyID string`, `ExpiresAtMS, RetryAfterSeconds int64`, `Ban *BanRecord`, `Degraded bool`, `Reason Reason`; throttle retry is positive; absent expiry/retry is zero. |
| `BeginCommand`, `BeginResult` | Command: `Subject`, `RequestID`, `Rates []RateSpec`; result: `NowMS int64`, `Fences map[Scope]string`, `SuppressedUntilMS map[Scope]int64`, `Bans []BanRecord`, `ThrottlePolicyID string`, `RetryAfterSeconds int64`. |
| `ObserveCommand`, `ObserveResult` | Command: `Subject`, `RequestID`, `Revision string`, `AdmittedAtMS int64`, `Fences map[Scope]string`, `Policies []MatchSpec`; result: `NowMS int64`, `Bans []BanRecord`, `Rejected map[Scope]Reason`. Return bans only for this triggering ID or its valid replay, never another already-admitted request's later ban. |
| `UnbanRequest`, `UnbanResult` | Request: `Mode`, `Scope`, `Application string`, `IP netip.Addr`, `OperationID string`, `SuppressFor time.Duration`, `Reason string`; result: `StateExisted, Replayed, RemainingApplicationBansEvaluated bool`, `Nonce string`, `ResetAtMS, SuppressedUntilMS int64`, `OtherBan *BanRecord`. Global reset omits application and reports application bans unevaluated. |
| `InspectRequest`, `InspectResult` | Request: `Subject Subject`; result: `Bans []BanRecord`, `SuppressedUntilMS map[Scope]int64`; include both scopes. |
| `ListRequest`, `ListResult` | Request: `Mode`, `Scope`, `Application, Cursor string`, `Limit int`; result: `Bans []BanRecord`, `Cursor string`, `Examined int`. |
| `StoreError` | `Reason Reason`, `Uncertain bool`, `Err error`; implement `error` without exposing secrets. Finite reason values: `invalid_identity`, `timeout`, `connection`, `read_only`, `oom`, `wrong_type`, `malformed_reply`, `saturated`, `budget_exhausted`, `stale_generation`, `expired_admission`, `clock_regression`, `evidence_overflow`, `field_limit`, `entropy_failure`. |
| Admin errors | Sentinel errors `ErrOperationConflict`, `ErrCursorExpired`, `ErrCursorMismatch`, `ErrCursorCapacity`, `ErrScanBatchTooLarge`; Task 7 maps them to HTTP status without treating invalid admin input as request-policy degradation. |

- [ ] Write the named tests with a recording fake Store: `TestEngineDisabledAndExempt` asserts zero store calls; `TestEngineSelectors` asserts ID OR exact tag, score AND valid, phases 1/2 only, and one strike per policy; `TestEngineRawPathSelectors` asserts `/login` differs from `/%6cogin` and keys use policy fingerprints; `TestEngineShadowStopsEvidence` asserts `Action=none`, the correct `WouldAction`, and zero Observe calls after shadow ban/throttle.
- [ ] Add `TestEngineAdmissionAge`: local monotonic age exactly 30s can reach Store, greater than 30s cannot; unusable Begin admission causes zero Observe calls; mutations of caller-owned config/evidence after capture cannot alter the operation. Redis-time age is independently tested in Task 4.
- [ ] Run `go test -race ./internal/autoban -run '^TestEngine' -count=1`; confirm failure because the package/API is missing.
- [ ] Implement the contracts and engine selection in these files. Capture one snapshot, reject incomplete/overflowed evidence entirely, prefer global ban explanation, map typed store failures to degradation, and retain one remaining store budget. No Coraza/ActionWriter references enter this package.
- [ ] Rerun the focused command; require every new assertion to pass with deterministic fake time and no Redis.
- [ ] Commit only the new package files: `git add internal/autoban`; `git commit -m "feat: define autoban contracts and policy engine"`.

### Task 2: Compile typed configuration without runtime side effects

**Files:** Modify `config.go`; create `config_autoban.go`, `config_autoban_test.go`, `internal/autoban/config.go`, and `config_test.go` within that package.

**Interfaces:** Consume Task 1 `Config`; produce `func Compile(input ConfigInput) (Config, error)` in `internal/autoban/config.go`, plus `RedisConfig` for connection/TLS/secret settings. Root `compileAutoban(c *config) (autoban.Config, autoban.RedisConfig, error)` translates typed YAML; it never opens a Redis connection or listener.

- [ ] Add `TestAutobanConfig` cases: defaults disabled/observe/20ms/50ms/128; opt-in per app; key prefix and policy/admin operation IDs match `[A-Za-z0-9._-]{1,64}`; reject prefix glob/separator characters. Participating app names are unique, nonempty, at most 256 UTF-8 bytes, without control characters; those extra restrictions do not affect legacy/disabled apps. Test all Global Constraints boundaries, including whole-millisecond periods; only explicitly enabled global match entries; invalid CIDR, unknown fields, mixed policy-type fields, empty match selectors, unsupported failure mode, and overflow all fail.
- [ ] Add `TestAutobanSecretsAndTLS`: disabled plus nonexistent password file succeeds without reading it; enabled unreadable secret fails; trim exactly one trailing newline; embedded NUL and incomplete certificate pair fail; TLS verification cannot be disabled; standalone requires one address and no master name, Sentinel requires a master name and at least one address. `TestAutobanFingerprint` asserts selector order normalization, distinct IDs produce distinct hashes even with identical semantics, global hashes stay equal across apps, and every semantic change alters the hash.
- [ ] Run `go test -race ./... -run '^(TestAutobanConfig|TestAutobanSecretsAndTLS|TestAutobanFingerprint)$' -count=1`; confirm tests fail for missing validation.
- [ ] Implement typed schema and compilation, preserving `KnownFields(true)` and existing WAF fields. Validate the exact spec example rule `id:190100`, `phase:1,pass,nolog`, tag `autoban/secret-probe` with Coraza `v3.8.1`; compile exemptions and selectors once, clone mutable input collections, and redact secret errors.
- [ ] Rerun the focused command; require PASS, including every lower/upper boundary and one value outside each bound.
- [ ] Commit: `git add config.go config_autoban.go config_autoban_test.go internal/autoban/config.go internal/autoban/config_test.go`; `git commit -m "feat: validate autoban configuration offline"`.

### Task 3: Add the bounded Redis adapter and real-store fixture

**Files:** Modify `go.mod`, `go.sum`; create `internal/autoban/redis.go`, `keys.go`, `redis_test.go`, `redis_integration_test.go`, and `integration/autoban/compose.yaml` with a Redis-only service initially.

**Interfaces:** Produce `func NewRedisStore(config RedisConfig) (*RedisStore, error)` and `func (s *RedisStore) Close() error`. Implement Task 1 Store operations through one shared primary pool; Task 4 supplies script bodies. Constructor errors represent local configuration errors; unreachable Redis must not prevent degraded runtime startup.

- [ ] Add `TestRedisBudgetAndNoReplay`: with operation timeout 50ms and budget 50ms, a 40ms first operation leaves 10ms; intervening WAF time leaves that budget unchanged; earlier parent deadlines win; saturation returns immediately; ambiguous timeout performs one command attempt. Explicit NOSCRIPT recovery shares the same deadline. `TestRedisKeys` asserts mapped IPv4 equivalence, collision-free app encoding, mode isolation, and no raw path/header in keys.
- [ ] Add `TestRedisFailures` cases for disconnect, read-only, OOM, wrong type, malformed replies, and canceled contexts: typed degradation, uncertain mutations identified, no retry. Add integration-tag `TestRedisConnection` asserting real Redis TIME, primary connectivity, and bounded cancellation; fixture setup requires `AUTOBAN_REDIS_ADDR`, with missing/unreachable Redis calling `t.Fatal`, never `t.Skip`.
- [ ] Run `go test -race ./internal/autoban -run '^TestRedis(Budget|Keys|Failures)' -count=1`; confirm failure before implementation.
- [ ] Pin a compatible `go-redis/v9` release, run `go mod tidy`, and implement primary/Sentinel/TLS setup, immediate concurrency acquisition, strict replies, and bounded script calls. Configure fixture Redis `7.2`, `noeviction`, and host binding `127.0.0.1:16379`; isolate tests by generated dedicated key prefixes.
- [ ] Start the future fixture with `docker compose -f integration/autoban/compose.yaml up -d --wait redis`; rerun unit tests and `AUTOBAN_REDIS_ADDR=127.0.0.1:16379 go test -race -v -tags=integration ./internal/autoban -run '^TestRedisConnection' -count=1`. Never use a fake Redis for Lua semantics; Task 9 adds real Sentinel/TLS coverage.
- [ ] Commit: `git add go.mod go.sum internal/autoban/redis* internal/autoban/keys.go integration/autoban/compose.yaml`; `git commit -m "feat: add bounded shared Redis transport"`.

### Task 4: Implement atomic admission, strikes, rates, and reset

**Files:** Create `internal/autoban/scripts.go`, `lua/begin.lua`, `lua/observe.lua`, `lua/unban.lua`, `lua/inspect.lua`, and `redis_policy_integration_test.go`; update `redis.go` and `keys.go`. All `lua/` paths are inside `internal/autoban/`.

**Interfaces:** Implement Task 1 Store command/result contracts, including exact `func (s *RedisStore) Unban(ctx context.Context, request UnbanRequest) (UnbanResult, error)`. Every accessed key is explicit; use Redis TIME, fixed ban expiry, and logical field expiry.

- [ ] Write these integration-tag tests against real Redis; use seeded state for boundaries, server-returned timestamps, and bounded expiry polling rather than timing guesses:

| Test | Exact assertions |
| --- | --- |
| `TestRedisWindowCutoff` | Active interval `(now-window, now]`; cutoff entry excluded; threshold 1 triggers on first distinct ID; duplicate triggering Observe returns identical expiry and does not extend TTL. |
| `TestRedisConcurrentThreshold` / `TestRedisConcurrentFirstStrike` | Threshold 3: exactly one successful trigger; a separately admitted request is not retroactively denied; concurrent clean admissions remain valid when another creates the first strike. |
| `TestRedisFreshWindows` | Window 60s, ban 30s: activation clears every match revision but preserves rate fields; after expiry the next match has count 1. Banned Begin creates no fields and never extends expiry. |
| `TestRedisScopesAndModes` | Application isolation; global explanation wins when both bans exist; disabled app excluded; observe keys cannot enforce or migrate on mode switch. Longest duration wins, ties choose lexicographic policy ID. |
| `TestRedisRateAllOrNothing` | Requests 20/10s, burst 10: first 10 accepted, 11th throttled with retry 1; one token refills after 500ms; another rejecting overlapping bucket causes zero consumption everywhere; rate rejection creates no ban/strike. |
| `TestRedisFenceABA` / `TestRedisUnbanReset` | Old admission rejected during live new fence and after its 120s expiry by age; exact age 30s allowed, greater rejected; negative Redis elapsed rejected. Reset clears all revisions/buckets in one scope, preserves the other, allows rates during 60s match suppression, and rejects old trigger receipts before lookup. |
| `TestRedisAdminReceipt` | Same mode/scope/app/IP/operation-ID tuple and input within 120s returns original nonce/times with `Replayed=true`, without refreshing TTL; changed content conflicts; another subject is independent; global reset reports application bans unevaluated; receipt expires after 120s. |
| `TestRedisPreflightBounds` | Invalid second scope, future stored update/refill/strike timestamps, 65th retained field, 64KiB overflow, 4MiB hash overflow, and unsafe arithmetic fail before either scope mutates; future timestamps yield `clock_regression` even for an age-valid admission. Prune expired fields first; post-mutation failure is uncertain, never rollback. |
| `TestRedisCleanAdmission` | With no applicable rates: repeated clean Begin leaves zero state/receipt keys; reads, denied traffic, and fence lookup do not refresh TTL; ordinary state expiry does not invalidate age-valid admissions. |

- [ ] Run `AUTOBAN_REDIS_ADDR=127.0.0.1:16379 go test -race -v -tags=integration ./internal/autoban -run '^TestRedis(Window|Concurrent|Fresh|Scopes|Rate|Fence|Unban|Admin|Preflight|Clean)' -count=1`; confirm failures before adding scripts.
- [ ] Implement all scripts with preflight of both scopes before mutation; no transactional rollback assumption. Reject future stored timestamps without moving refill time backwards; use integer-scaled bucket units, clamp elapsed to time-to-full before multiplication, consume all-or-none, and round maximum required refill delay up to seconds (minimum 1). On ban creation clear every scope match field, retain triggering ID, preserve rates. Enforce live-fence/dual-age rules and 120s normalized-input-digest admin receipts from spec §10.
- [ ] Rerun the focused integration command; require PASS including real expiry and the full fence-retention scenario. Do not shorten production limits to make tests pass.
- [ ] Commit: `git add internal/autoban`; `git commit -m "feat: implement atomic shared autoban state"`.

### Task 5: Bridge request evidence and preserve transaction ownership

**Files:** Modify `internal/application.go`, `internal/agent.go`; create `internal/autoban_bridge.go` and `internal/autoban_bridge_test.go`.

**Interfaces:** Add `Autoban *autoban.Engine` to `internal.AppConfig`. Bridge calls Task 1 engine APIs; `Application.HandleRequest` retains its existing signature and WAF-error return behavior. Produce all eight transaction-scoped variables from spec §9, using the existing configured SPOE prefix.

- [ ] Add `TestAutobanResolvedIdentity`: unknown incoming app resolves to configured default; forged forwarded headers do not change `src-ip`; mapped IPv4 shares state; native IPv6 is individual; invalid/missing IP is `invalid_identity` and WAF still runs. Policy request IDs use 128 cryptographically random bits, independent of HTTP/Coraza IDs; entropy failure degrades without using a fallback identity.
- [ ] Add `TestAutobanEvidenceFinalization`: one aggregate Observe after phase-1/body-limit/phase-2 interruption; one contribution per policy despite duplicate rules/variables; `nolog`, empty message, and ID 123456 work; score absent/invalid fails score selection; phase 3/4/5 and non-interruption errors write no evidence; 257 selected records degrade without partial bans. Mutating/releasing source buffers cannot alter the copied evidence.
- [ ] Add `TestAutobanTransactionOwnership` across response-check on/off and request/response detect-only: early policy denial creates zero WAF transactions; new local denial logs/closes once and caches zero; admitted request retains existing correlation; expiry adds no evidence. `TestAutobanDecisionComposition` preserves WAF deny/drop/redirect/error and writer-failure paths; policy-only ban is separate; timeout keeps WAF result and sets no `error`; each request initializes all policy variables, with `autoban_until=ceil(expires_at_ms/1000)`.
- [ ] Run `go test -race ./internal -run '^TestAutoban' -count=1`; confirm failures before bridge changes.
- [ ] Implement one request-finalization path before logging/cache transfer/close. Initialize policy variables, generate the policy request ID for an enabled request, parse trusted identity, call Begin before WAF creation, snapshot selected scalar evidence, call Observe at most once, and compose the origin-forwarding decision independently of WAF metrics. Do not route policy outcomes through `ErrInterrupted` or invent `ruleid` values.
- [ ] Rerun the focused command; require PASS and exact create/close/cache/metric counts, including unknown Observe outcomes and actual WAF errors.
- [ ] Commit: `git add internal/application.go internal/agent.go internal/autoban_bridge.go internal/autoban_bridge_test.go`; `git commit -m "feat: integrate autoban request decisions with SPOE"`.

### Task 6: Own runtime startup, reload, and bounded shutdown

**Files:** Modify `main.go`, `config.go`; create `autoban_runtime.go`, `autoban_runtime_test.go`.

**Interfaces:** Produce root `newAutobanRuntime(ctx context.Context, compiled autoban.Config, redisConfig autoban.RedisConfig) (*autobanRuntime, error)` and `func (r *autobanRuntime) Shutdown(ctx context.Context) error`. Runtime owns one Store; replacement engines share it and are attached before `Agent.ReplaceApplications` publishes new applications.

- [ ] Add `TestAutobanValidateOffline`: `-validate` succeeds with unavailable Redis, reads required enabled secrets, compiles example rules, and creates no connection/listener/keys; disabled mode never reads secrets. `TestAutobanStartupUnavailable` asserts SPOA startup succeeds and policy reports degraded.
- [ ] Add `TestAutobanReloadSnapshot`: pause after Begin, reload threshold/mode/exemptions, then old Observe uses its original fingerprint/mode; invalid replacement retains the old engine; app enable/mode and top-level mode reload; every restart-only change fails before publication. `TestAutobanShutdown` asserts cancel reaches active calls and pool closes once only after their bounded exit.
- [ ] Run `go test -race . -run '^TestAutoban(Validate|Startup|Reload|Shutdown)' -count=1`; confirm failures before lifecycle wiring.
- [ ] Wire actual client/admin initialization after the existing validation-only return. Validate every replacement before publishing; preserve runtime and store on policy-only reload; retain the existing response-correlation limitation without expanding reload guarantees. Stop admission, cancel policy calls, wait within their budgets, then close the pool.
- [ ] Rerun the focused command and `go test -race ./...`; require PASS, including no pool retirement during an admitted request.
- [ ] Commit: `git add main.go config.go autoban_runtime.go autoban_runtime_test.go`; `git commit -m "feat: manage autoban runtime lifecycle"`.

### Task 7: Expose bounded inspection and administrative reset

**Files:** Create `internal/autoban/admin.go`, `admin_socket.go`, `admin_test.go`, `admin_integration_test.go`; update `redis.go` and root `autoban_runtime.go`.

**Interfaces:** Produce `func NewAdminHandler(store Store, snapshot func() Config) http.Handler`; bind only the configured Unix socket. Consume Task 1 Inspect/List/Unban contracts and Task 4 reset/receipt semantics. Implement routes and JSON field names exactly as spec §10.

- [ ] Add `TestAdminValidation`: invalid mode/scope/app/IP/operation ID, empty reason, suppression outside 0–24h, and body above 8192 bytes fail; malformed input is 400, changed receipt content within the same tuple 409, unavailable/uncertain store 503. Application reset reports current global ban; global reset returns `remaining_application_bans_evaluated=false`; replay returns original timestamped result.
- [ ] Add `TestAdminSocket`: socket mode is exactly `0600`, no TCP listener, regular-file bind path is unchanged on failure. `TestAdminPagination` seeds state/fence/receipt keys; inspects at most 1000 keys under a 100ms client deadline, returns at most requested 1–100 active records, excludes fences/receipts, preserves surplus SCAN keys, and permits empty pages with continuation. No `KEYS`; do not claim COUNT bounds server work.
- [ ] Add `TestAdminCursorBounds`: 32 live cursors maximum, 1000 pending keys maximum per cursor, 120s retention; expired/unknown/wrong-instance cursor returns 410, query mismatch 400, capacity/oversized batch 503. Failed calls leave prior cursor unadvanced; repeated pages cannot lose unconsumed keys; restart requires a fresh scan.
- [ ] Run `go test -race ./internal/autoban -run '^TestAdmin' -count=1`; confirm failures before API implementation.
- [ ] Implement body/input validation, opaque query/process-bound cursor state with lazy cleanup, and graceful socket shutdown. Validate app-name syntax without making historical state inaccessible after policy removal. Normalize and digest all mutation content; use `<prefix>:v1:<mode>:{<ip_hex>}:admin:<scope_id>:<operation_id>`; application is part of scope ID only for application reset. Preserve unconsumed SCAN batches and documented weak consistency.
- [ ] Rerun unit tests and `AUTOBAN_REDIS_ADDR=127.0.0.1:16379 go test -race -v -tags=integration ./internal/autoban -run '^TestAdmin' -count=1`; require PASS against real reset/receipt/pagination behavior.
- [ ] Commit: `git add internal/autoban/admin* internal/autoban/redis.go autoban_runtime.go`; `git commit -m "feat: add Unix socket autoban administration"`.

### Task 8: Add bounded observability and deployable examples

**Files:** Create `internal/autoban/metrics.go`, `audit.go`, `observability_test.go`, `docs/autoban.md`, `example/autoban/coraza-spoa.yaml`; modify `internal/autoban_bridge.go`, `internal/metrics.go`, `main.go`, `README.md`, `example/haproxy/haproxy.cfg`, and `example/haproxy/coraza.cfg`.

**Interfaces:** Consume Task 1 decision/ban metadata. Produce the six metrics and bounded configuration revision metric in spec §10; initialize exact SPOE variables from spec §9. Keep existing WAF metrics and health liveness semantics.

- [ ] Add `TestAutobanObservability`: labels exclude IP/request ID/URL/untrusted app/error text; removed revision labels disappear; denied-before-WAF leaves existing WAF counters unchanged. Ban audit contains canonical subject, scope, policy/fingerprint, request and optional transaction IDs, count/window/fixed expiry; secrets/cookies/body/raw match data are absent. Repeated errors/denials are sampled; activation/unban/observed expiry/degradation transitions remain explainable.
- [ ] Add `TestAutobanHealth`: Redis outage reports policy degradation separately while existing `/healthz` remains SPOA liveness. Run `go test -race ./... -run '^TestAutoban(Observability|Health)$' -count=1`; confirm failures before instrumentation.
- [ ] Implement instrumentation and a separate readiness detail for policy dependency state. Add the exact spec `429` with `Retry-After` and `403` HAProxy rules after existing WAF error/deny/drop/redirect handling, with one request-group invocation; never expose policy IDs in public headers. Keep the general example disabled; place the complete opt-in observe example and `id:190100` rule in `example/autoban/`.
- [ ] Write `docs/autoban.md`: trusted client setup, aliases/burst semantics, standalone/Sentinel/TLS/secrets/noeviction capacity, bounded admin curl examples, failover/deletion limits, revision rollout, response-affinity limitation, disabled→observe→enforce rollout, exemption plus scoped unban, and no body-buffering avoidance claim. Application rollback uses observe/disable plus SIGHUP; complete top-level disable requires restart.
- [ ] Rerun focused tests, then `go run mage.go build` and `./build/coraza-spoa -validate -config example/autoban/coraza-spoa.yaml` with fixture secret paths prepared; require successful offline validation. Actual HAProxy matrix checks are Task 9.
- [ ] Commit the listed files: `git add internal/autoban internal/autoban_bridge.go internal/metrics.go main.go README.md docs/autoban.md example`; `git commit -m "feat: document and observe autoban enforcement"`.

### Task 9: Prove cross-node enforcement and run the release gates

**Files:** Expand `integration/autoban/compose.yaml`; create `run.sh`, `cluster_integration_test.go`, `README.md`, and fixture configs under `integration/autoban/`; create `.github/workflows/autoban.yml`; modify `internal/e2e_test.go` only where sharing existing harness behavior is necessary.

**Interfaces:** Future `AUTOBAN_HAPROXY_VERSION=2.8 ./integration/autoban/run.sh` builds/starts real Redis, two SPOA processes, two HAProxy processes, and an origin; it exports `AUTOBAN_REDIS_ADDR` and fixture endpoint/socket paths, runs `go test -race -v -tags=integration ./internal/autoban ./integration/autoban -count=1`, and tears down only its dedicated project. Missing dependencies/fixtures are hard failures.

- [ ] Add `TestClusterSharedBan` with a minimal `pass,nolog` match-rule fixture whose tested path is not blocked by CRS: first two matching requests through A allowed, third through B returns 403, later A returns 403; an origin spy proves the crossing and banned requests were never forwarded. Cross-node inspect/unban affects both; other app/scope remains correct. `TestClusterRates` asserts shared burst/refill and actual HTTP 429 with positive Retry-After; rate-only traffic creates no bans.
- [ ] Add `TestClusterPersistentConnections`, `TestClusterEncodedPaths`, and `TestClusterResponseOwnership`: keep-alive and HTTP/2 requests after a ban are rechecked; raw encoded aliases match only configured selectors; trusted source ignores forged forwarding headers; response-check/detect-only matrices create no orphan/duplicate close/false expiry or response-derived strikes. Preserve existing WAF redirect/drop/deny precedence.
- [ ] Add `TestClusterFailureAndReload`: disconnect/read-only/OOM and injected lost Observe reply preserve current WAF result with no command replay; next request sees any committed ban; active-request reload keeps its snapshot; cross-node reset fences older observation. Add `TestClusterSentinelTLS` using fixture primary/replica/Sentinel and temporary test certificates: verified TLS succeeds, wrong CA fails, policy reads/writes target the primary, and failover produces bounded degradation without an acknowledged-write durability claim. Run focused tests first and record expected failures before completing fixtures.
- [ ] Implement CI matrix `2.8`, `3.0`, `3.2`; syntax-check both HAProxy configs in the matching container before HTTP tests. Run the future `run.sh` command once per version; require every named cluster test to pass, with no integration skips.
- [ ] Run existing gates from repository root: `go test -race ./...`, `go test -race -v -tags=e2e ./internal`, `go run mage.go build`, then `FTW_HAPROXY_VERSION=2.8 go run mage.go ftw`, repeated for `3.0` and `3.2`. Keep auto-ban absent/disabled in CRS FTW and confirm legacy results.
- [ ] Measure clean traffic, new scanner IPs, banned IPs, and Redis outage against disabled baseline. Record hardware, policy count, concurrency, payload sizes, p50/p95/p99 request/store latency, throughput, Redis memory/key growth, and budget behavior in `docs/autoban-performance.md`. Obtain service SLO latency/capacity thresholds before production enforcement; report actual measurements, not estimates presented as results.
- [ ] Commit: `git add integration/autoban .github/workflows/autoban.yml internal/e2e_test.go docs/autoban-performance.md`; `git commit -m "test: verify cluster autoban across HAProxy versions"`.

## Acceptance Coverage

| Spec acceptance | Owning task and named proof |
| --- | --- |
| AB-01 | Tasks 2/6/9: `TestAutobanSecretsAndTLS`, `TestAutobanValidateOffline`, all existing gates with feature disabled. |
| AB-02, AB-22 | Task 9: `TestClusterSharedBan`, `TestClusterFailureAndReload`; two actual SPOA and two HAProxy processes. |
| AB-03, AB-07 | Tasks 1/4/9: `TestEngineShadowStopsEvidence`, `TestRedisScopesAndModes`, `TestClusterSharedBan`. |
| AB-04, AB-05 | Tasks 1/5: `TestEngineSelectors`, `TestAutobanEvidenceFinalization`. |
| AB-06 | Tasks 3/5/9: `TestRedisKeys`, `TestAutobanResolvedIdentity`, `TestClusterEncodedPaths`. |
| AB-08, AB-09 | Tasks 4/5/9: `TestRedisConcurrentThreshold`, `TestRedisWindowCutoff`, `TestRedisFreshWindows`, `TestClusterSharedBan`. |
| AB-10, AB-16 | Tasks 4/9: `TestRedisRateAllOrNothing`, `TestClusterRates`, `TestClusterPersistentConnections`. |
| AB-11, AB-12 | Tasks 4/7/9: `TestRedisFenceABA`, `TestRedisUnbanReset`, `TestRedisAdminReceipt`, `TestClusterFailureAndReload`. |
| AB-13, AB-14 | Tasks 3/5/9: `TestRedisBudgetAndNoReplay`, `TestRedisFailures`, `TestAutobanDecisionComposition`, `TestClusterFailureAndReload`. |
| AB-15 | Tasks 1/2/4/5: `TestEngineAdmissionAge`, `TestAutobanConfig`, `TestRedisFenceABA`, `TestRedisPreflightBounds`, `TestAutobanEvidenceFinalization`. |
| AB-17, AB-18 | Tasks 5/6/9: `TestAutobanTransactionOwnership`, `TestAutobanReloadSnapshot`, `TestAutobanShutdown`, `TestClusterResponseOwnership`. |
| AB-19 | Tasks 2/6/8: `TestAutobanConfig`, `TestAutobanValidateOffline`, compiled documented example. |
| AB-20, AB-21 | Tasks 7/8: `TestAdminValidation`, `TestAdminSocket`, `TestAdminPagination`, `TestAdminCursorBounds`, `TestAutobanObservability`, `TestAutobanHealth`. |

The final implementation review must attach gate outputs and measured performance, verify every row above, and preserve the design's explicit limitations. This document authorizes no production rollout by itself.
