#!/usr/bin/env bash
# Docker image smoke test (#124): build the broker image and prove it actually BOOTS and serves —
# a broken Dockerfile (bad entrypoint, missing dist path, unreachable Postgres) is otherwise
# discovered only at deploy time. The image is the quick-start artifact.
#
# Vouchr is PostgreSQL-only, so the smoke stands up a throwaway Postgres container on a private
# docker network and points the broker at it — the same shape a real deployment uses.
#
# Runnable locally (`npm run docker-smoke`, needs Docker) and in CI. No external credentials.
set -euo pipefail

IMAGE=vouchr-smoke
NAME=vouchr-smoke-test
PG_NAME=vouchr-smoke-pg
NET=vouchr-smoke-net
PORT=3010 # avoid clashing with a local dev broker on 3000
# Distinctive secret values so the log-leak check below is meaningful (not real secrets).
SECRET="smoke-identity-secret-DO-NOT-LOG-$$"
MASTER_KEY="$(openssl rand -base64 32)"
PROVIDERS='[{"id":"smoke","credential":"key","egressAllow":["api.example.com"]}]'

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker build"
docker build -t "$IMAGE" . >/dev/null

echo "==> start a throwaway Postgres on a private network"
docker network create "$NET" >/dev/null
docker run -d --name "$PG_NAME" --network "$NET" \
  -e POSTGRES_USER=vouchr -e POSTGRES_PASSWORD=vouchr -e POSTGRES_DB=vouchr \
  postgres:16-alpine >/dev/null
echo "==> wait for Postgres to accept connections (30s timeout)"
for i in $(seq 1 30); do
  if docker exec "$PG_NAME" pg_isready -U vouchr >/dev/null 2>&1; then echo "    pg ready after ${i}s"; break; fi
  [ "$i" = 30 ] && { echo "FAIL: Postgres never became ready"; docker logs "$PG_NAME"; exit 1; }
  sleep 1
done

DB_URL="postgres://vouchr:vouchr@${PG_NAME}:5432/vouchr"

# The runtime no longer creates tables (it connects with a DML-only role and fails closed on an
# unmigrated DB), so migrate the schema first using the SAME image. `vouchr migrate` is idempotent
# and advisory-locked. Fail the smoke if it errors — a broken migrate path must not reach a deploy.
echo "==> migrate the schema (vouchr migrate) against Postgres"
docker run --rm --network "$NET" \
  -e VOUCHR_DATABASE_URL="$DB_URL" \
  "$IMAGE" node dist/bin/vouchr.js migrate \
  || { echo "FAIL: vouchr migrate errored"; exit 1; }

echo "==> run the broker with minimal env (one key provider), pointed at the migrated Postgres"
docker run -d --name "$NAME" --network "$NET" \
  -e VOUCHR_IDENTITY_SECRET="$SECRET" \
  -e VOUCHR_MASTER_KEY="$MASTER_KEY" \
  -e VOUCHR_PROVIDERS="$PROVIDERS" \
  -e VOUCHR_PORT="$PORT" \
  -e VOUCHR_DATABASE_URL="$DB_URL" \
  -p "$PORT:$PORT" "$IMAGE" >/dev/null

# Poll /readyz, not /healthz: /healthz is bare liveness (no db), so it can't tell a booted server from
# a usable one. /readyz does a real SELECT 1 through the store, so 200 proves listening AND store-ready.
echo "==> poll /readyz until 200 (30s timeout)"
ok=""
for i in $(seq 1 30); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/readyz" || true)" = "200" ]; then
    ok=1; echo "    readyz 200 after ${i}s"; break
  fi
  # If the container died, fail fast with its logs instead of waiting out the timeout.
  if [ -z "$(docker ps -q -f name="$NAME")" ]; then echo "FAIL: container exited early"; docker logs "$NAME"; exit 1; fi
  sleep 1
done
[ -n "$ok" ] || { echo "FAIL: /readyz never returned 200"; docker logs "$NAME"; exit 1; }

echo "==> the startup log names providers but leaks NO secret"
LOGS="$(docker logs "$NAME" 2>&1)"
echo "$LOGS" | grep -q "broker listening" || { echo "FAIL: no listening line"; echo "$LOGS"; exit 1; }
if echo "$LOGS" | grep -qF "$SECRET" || echo "$LOGS" | grep -qF "$MASTER_KEY"; then
  echo "FAIL: a secret value appeared in the container logs"; exit 1
fi
echo "    logs clean of secrets"

echo "==> PASS: image builds, boots, serves /readyz (store reachable), logs no secrets"
