# Auto-ban performance measurement

This document records the measurement procedure for auto-ban. **No measured
results are presented in this revision.** The release gate requires real
measurements against a deployed SLO before production enforcement; estimates
must never be reported as results.

## Procedure

1. Deploy the cluster fixture from `integration/autoban/` (or an equivalent
   production-shaped environment) with the same HAProxy version matrix used by
   CI: 2.8, 3.0, and 3.2.
2. Record the environment: CPU model and count, memory, kernel, Redis version,
   HAProxy version, Go build version, policy count, configured concurrency, and
   payload sizes.
3. For each load shape below, run a warm-up followed by a measured window and
   collect p50/p95/p99 request and store latency, throughput, auto-ban store
   budget consumption, Redis memory, and key growth:
   - clean traffic against the disabled baseline,
   - clean traffic with auto-ban enabled in observe mode,
   - a stream of new scanner IPs,
   - traffic from already-banned IPs,
   - a Redis outage (store degradation path).
4. Compare enabled runs against the disabled baseline at identical offered
   load. Confirm that WAF counters are unchanged for early policy denials and
   that no store operation exceeds its configured budget.
5. Obtain service SLO latency and capacity thresholds from the owning team,
   then decide whether the measured headroom supports enforcement. Auto-ban
   defaults to observe and does not authorize rollout by itself.

## Result table (to be filled by a real measurement run)

| Hardware / version | Load shape | Policies | Concurrency | Payload | p50 | p95 | p99 | RPS | Store budget | Redis memory / keys |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |

Until this table is populated with observed data, treat the performance impact
of auto-ban as unmeasured.
