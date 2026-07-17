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
DEPLOYMENT_ID="smoke-deployment" # #212 required: binds identity assertions to this deployment
MASTER_KEY="$(openssl rand -base64 32)"
PROVIDERS='[{"id":"smoke","credential":"key","egressAllow":["api.example.com"]}]'

ARB_NAME=vouchr-smoke-arb
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rm -f "$ARB_NAME" >/dev/null 2>&1 || true
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
  -e VOUCHR_DEPLOYMENT_ID="$DEPLOYMENT_ID" \
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

# The reference manifest pins no UID and requires a read-only root filesystem, so the image must run
# under an ARBITRARY numeric non-root user (a Restricted platform assigns one from its range) with
# root read-only. Prove that here, not only at deploy time (#216, #258).
echo "==> the image boots as an arbitrary non-root UID with a read-only root filesystem"
ARB_PORT=3011
docker run -d --name "$ARB_NAME" --network "$NET" \
  --user 12345:12345 --read-only --tmpfs /tmp \
  -e VOUCHR_IDENTITY_SECRET="$SECRET" \
  -e VOUCHR_DEPLOYMENT_ID="$DEPLOYMENT_ID" \
  -e VOUCHR_MASTER_KEY="$MASTER_KEY" \
  -e VOUCHR_PROVIDERS="$PROVIDERS" \
  -e VOUCHR_PORT="$ARB_PORT" \
  -e VOUCHR_DATABASE_URL="$DB_URL" \
  -p "$ARB_PORT:$ARB_PORT" "$IMAGE" >/dev/null
arb_ok=""
for i in $(seq 1 30); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ARB_PORT/readyz" || true)" = "200" ]; then
    arb_ok=1; echo "    arbitrary-UID (12345) + read-only root: readyz 200 after ${i}s"; break
  fi
  if [ -z "$(docker ps -q -f name="$ARB_NAME")" ]; then echo "FAIL: arbitrary-UID container exited early"; docker logs "$ARB_NAME"; exit 1; fi
  sleep 1
done
[ -n "$arb_ok" ] || { echo "FAIL: arbitrary-UID/read-only container never served /readyz"; docker logs "$ARB_NAME"; exit 1; }

echo "==> PASS: image builds, boots (default + arbitrary UID / read-only root), serves /readyz, logs no secrets"
