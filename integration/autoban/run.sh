#!/usr/bin/env bash
set -euo pipefail

VERSION="${AUTOBAN_HAPROXY_VERSION:-2.8}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE="$HERE/compose.yaml"
PROJECT="autoban-cluster-it"

cleanup() {
  docker compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
docker compose -p "$PROJECT" -f "$COMPOSE" up -d --wait --build
docker compose -p "$PROJECT" -f "$COMPOSE" exec -T redis redis-cli FLUSHALL >/dev/null

export AUTOBAN_REDIS_ADDR=127.0.0.1:16379
export AUTOBAN_HAPROXY_A=http://127.0.0.1:18080
export AUTOBAN_HAPROXY_B=http://127.0.0.1:18081

cd "$ROOT"
go test -race -v -tags=integration ./internal/autoban ./integration/autoban -count=1
