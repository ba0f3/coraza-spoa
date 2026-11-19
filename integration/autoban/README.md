# Cluster auto-ban integration fixture

This fixture starts real Redis, two SPOA processes, two HAProxy processes, and
an origin, then runs the cross-node auto-ban tests. Missing dependencies or an
unreachable fixture are hard failures; the tests never skip.

```sh
AUTOBAN_HAPROXY_VERSION=2.8 ./integration/autoban/run.sh
```

The script:

1. tears down only its dedicated Compose project (`autoban-cluster-it`),
2. builds the SPOA image from the repository, starts the stack, and flushes the
   fixture Redis,
3. exports `AUTOBAN_REDIS_ADDR`, `AUTOBAN_HAPROXY_A`, and
   `AUTOBAN_HAPROXY_B`,
4. runs `go test -race -v -tags=integration ./internal/autoban ./integration/autoban`,
5. tears down the dedicated project on exit.

Host endpoints: proxy A `http://127.0.0.1:18080`, proxy B
`http://127.0.0.1:18081`, Redis `127.0.0.1:16379`.

The fixture uses `noeviction` Redis and a shared `cluster-it` key prefix, so
both SPOAs enforce the same bans. State is flushed at startup. The HAProxy
configs perform the policy `429`/`403` checks after the existing WAF
error/deny/drop/redirect handling and with one request-group invocation.

Sentinel and TLS coverage is not yet included in this fixture; it remains a
release-gate item. See `docs/autoban-performance.md` for the measurement
procedure and the explicit statement that no results are recorded yet.
