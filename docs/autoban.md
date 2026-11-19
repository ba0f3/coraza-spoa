# Cluster-wide scanner auto-ban

Auto-ban shares scanner counters and temporary bans across every SPOA process
that points at the same Redis primary. HAProxy enforces the returned decision;
Coraza remains the rule engine. The feature is opt-in and disabled in all
general-purpose examples.

## Trusted client setup

Resolve the application and client address in HAProxy, then restrict the SPOA
listener to authorized proxies. The SPOA uses the *configured* application name
and the existing `src-ip` argument; it never parses forwarding headers or uses
incoming `app`/`Host` text as a Redis namespace or metric label. Addresses are
canonicalized with `Unmap`, so mapped IPv4 shares its IPv4 subject. Native IPv6
is an individual address; no prefix widening occurs. An invalid address
disables policy for that request (`invalid_identity`) while WAF processing
continues.

The policy request ID is 128 cryptographically random bits generated once per
request, independent of the Coraza transaction ID and any HTTP request-ID
header. V1 guarantees deduplication within one SPOE request group; it does not
claim exactly-once counting across duplicated SPOE deliveries.

## Aliases and burst semantics

Rate policies compare HAProxy's raw path literally. No second decoding pass is
performed: `/login` and `/%6cogin` are distinct unless both are configured.
Deployments must enumerate the aliases their origin accepts. Token buckets
start full and intentionally permit the configured burst; `requests`/`period`
set the refill rate, `burst` sets capacity. When any matching bucket lacks a
token, none are consumed and the request receives HTTP 429 with a positive
`Retry-After`. Rate rejection creates no ban and no match strike.

Match evidence comes from Coraza rule IDs or exact tags in phases 1 and 2, with
an optional anomaly-score AND condition. One strike per policy is recorded per
request. Only phases 1 and 2 count; response matches, log lines, and matched
variable counts do not.

## Deployment: standalone, Sentinel, TLS, secrets, capacity

- Standalone Redis requires exactly one address and no master name. Sentinel
  requires a master name and at least one Sentinel address. Policy reads and
  writes always target the primary.
- Redis 7.2+ is required. Native Redis Cluster is not supported.
- TLS always verifies the server; verification cannot be disabled. A
  certificate/key pair must be complete. Secret files have exactly one trailing
  newline trimmed and reject embedded NUL.
- Configure `maxmemory` with an explicit capacity plan and `noeviction`. OOM or
  read-only responses degrade policy; they never become a clean policy result.
- Key prefix, policy IDs, and admin operation IDs use 1–64 characters from
  `[A-Za-z0-9._-]`. Choose a prefix unique to the environment.

## Rolling out a policy

Start with `enabled: true`, `mode: observe`, and `on_store_error: continue_waf`.
Observe mode reports hypothetical `would_ban`/`would_throttle` and stops shadow
strike accumulation, but never creates an effective policy denial. Review the
ban audit and latency metrics, then switch to `enforce` per application or
globally. Application rollback uses observe/disable plus SIGHUP; a complete
top-level disable requires a restart. Policy changes require coordinated
rollout: compare the `coraza_autoban_config_info` revision across nodes.

Per-application enable/mode, top-level mode, policies, and exemptions reload.
Enabling, Redis connection/credentials/TLS/prefix/DB, store timing/concurrency,
and admin socket changes require restart and are rejected on reload.

## Administration

The API listens only on a Unix socket (default
`/run/coraza-spoa/autoban-admin.sock`, mode `0600`). Bodies are limited to 8 KiB.

```sh
# Inspect both scopes for one subject
curl --unix-socket /run/coraza-spoa/autoban-admin.sock \
  'http://localhost/v1/bans/inspect?mode=enforce&application=sample_app&ip=203.0.113.10'

# List active application bans (limit 1-100, opaque cursor)
curl --unix-socket /run/coraza-spoa/autoban-admin.sock \
  'http://localhost/v1/bans?mode=enforce&scope=application&application=sample_app&limit=100'

# Reset one scope with a 60s match suppression
curl --unix-socket /run/coraza-spoa/autoban-admin.sock \
  -H 'Content-Type: application/json' \
  -d '{"mode":"enforce","scope":"application","application":"sample_app","ip":"203.0.113.10","operation_id":"incident-42","suppress_for":"60s","reason":"false positive"}' \
  http://localhost/v1/bans/unban
```

Repeating the same operation tuple within 120 s returns the original timestamped
result with `replayed=true`; different content for that tuple returns 409.
A global reset clears only global state and reports
`remaining_application_bans_evaluated=false` — inspect applications separately.
Listing uses SCAN; COUNT is only a hint, internal Redis work is not bounded by
it, and pagination is weakly consistent. At most 32 cursors retain up to 1,000
pending keys each for 120 s, bound to the query and process. A restart requires a
fresh scan. Do not use `KEYS`.

## Failure, failover, and deletion limits

The only store-failure behavior is `continue_waf`: WAF processing and any WAF
denial are preserved, policy reports `policy_degraded=true` with a bounded
reason, and no generic SPOE error is produced. Ambiguous commands are never
replayed. Replication is asynchronous; an acknowledged ban is not guaranteed to
survive every failover. If keys are manually deleted or Redis is flushed,
continuity guarantees no longer apply — record and alert on the incident. A
large server-clock jump can also break fence history.

## Limitations

- Response-derived evidence is deferred. The existing response correlation cache
  is preserved but is not policy state and does not survive a configuration
  reload; a request holding its application snapshot still completes.
- The initial implementation saves WAF evaluation for banned requests but does
  not guarantee avoidance of HAProxy body buffering or SPOE body transfer.
- This document authorizes no production rollout by itself. Obtain service SLO
  latency and capacity thresholds before enabling enforcement.
