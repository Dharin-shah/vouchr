#!/usr/bin/env bash
# Docker image smoke + two-replica deployment proof (#124, #216). Builds the broker image — or takes the
# exact already-pushed digest via VOUCHR_SMOKE_IMAGE, so a release smokes what it signs instead of a
# rebuild — and proves the ONE supported production shape (vision.md § Production architecture):
#   - the image declares a numeric non-root user; both replicas run with a read-only root filesystem,
#     one as the image default uid and one as an arbitrary platform-assigned uid;
#   - `vouchr migrate` runs as a SEPARATE step with the schema-owner role; the replicas connect with
#     the DML-only role (which provably cannot CREATE) — the two roles from DEPLOYMENT.md § Migrations;
#   - two replicas serve /readyz against ONE PostgreSQL; startup logs leak no secret;
#   - rolling restart: each replica drains on SIGTERM (exit 0), restarts and returns ready while the
#     other replica answers every request (what an LB honouring /readyz sees: zero failed requests);
#   - graceful drain: a request in flight when SIGTERM arrives still receives its response;
#   - dependency failure: PostgreSQL down → /readyz 503 on every replica (LB pulls them) while
#     /healthz stays 200 (no restart storm); PostgreSQL back → /readyz 200 with no replica restart.
#
# Runnable locally (`npm run docker-smoke`, needs Docker) and in CI. No external credentials.
set -euo pipefail

IMAGE="${VOUCHR_SMOKE_IMAGE:-vouchr-smoke}"
NAME=vouchr-smoke-test # replica containers: $NAME-1, $NAME-2
PG_NAME=vouchr-smoke-pg
NET=vouchr-smoke-net
PORT1=3010 # avoid clashing with a local dev broker on 3000
PORT2=3011
# Distinctive secret values so the log-leak check below is meaningful (not real secrets).
SECRET="smoke-identity-secret-DO-NOT-LOG-$$"
DEPLOYMENT_ID="smoke-deployment" # #212 required: binds identity assertions to this deployment
MASTER_KEY="$(openssl rand -base64 32)"
PROVIDERS='[{"id":"smoke","credential":"key","egressAllow":["api.example.com"]}]'
# Two DB roles, exactly as deploy/k8s.yaml splits them: the migrate step is the only schema-owner
# user; every replica is DML-only.
OWNER_URL="postgres://vouchr_owner:owner-smoke@${PG_NAME}:5432/vouchr"
APP_URL="postgres://vouchr_app:app-smoke@${PG_NAME}:5432/vouchr"
TMP="$(mktemp -d)"

cleanup() {
  docker rm -f "$NAME-1" "$NAME-2" "$PG_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*"
  for c in "$NAME-1" "$NAME-2"; do echo "--- $c logs ---"; docker logs "$c" 2>&1 | tail -n 30 || true; done
  exit 1
}
# HTTP status of GET http://127.0.0.1:PORT/PATH ("000" on connection failure). /readyz is bounded ~2s.
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://127.0.0.1:$1$2" || true; }
# wait_code PORT PATH STATUS SECONDS LABEL — poll until PATH returns STATUS.
wait_code() {
  for i in $(seq 1 "$4"); do
    [ "$(code "$1" "$2")" = "$3" ] && { echo "    $5: $2 -> $3 after ${i}s"; return 0; }
    sleep 1
  done
  return 1
}
exit_code() { docker inspect -f '{{.State.ExitCode}}' "$1"; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

if [ -n "${VOUCHR_SMOKE_IMAGE:-}" ]; then
  echo "==> docker pull $IMAGE (the exact pushed digest — no rebuild)"
  docker pull "$IMAGE" >/dev/null
else
  echo "==> docker build"
  docker build -t "$IMAGE" . >/dev/null
fi

echo "==> start ONE throwaway Postgres on a private network"
docker network create "$NET" >/dev/null
docker run -d --name "$PG_NAME" --network "$NET" \
  -e POSTGRES_USER=vouchr -e POSTGRES_PASSWORD=vouchr -e POSTGRES_DB=vouchr \
  postgres:16-alpine >/dev/null
wait_pg() {
  for i in $(seq 1 30); do
    if docker exec "$PG_NAME" pg_isready -U vouchr >/dev/null 2>&1; then echo "    pg ready after ${i}s"; return 0; fi
    sleep 1
  done
  echo "FAIL: Postgres never became ready"; docker logs "$PG_NAME"; exit 1
}
wait_pg

echo "==> create the schema-owner and DML-only roles (the SQL from DEPLOYMENT.md § Migrations)"
docker exec -i "$PG_NAME" psql -v ON_ERROR_STOP=1 -q -U vouchr -d vouchr >/dev/null <<'SQL'
CREATE ROLE vouchr_owner LOGIN PASSWORD 'owner-smoke';
GRANT ALL ON SCHEMA public TO vouchr_owner;
CREATE ROLE vouchr_app LOGIN PASSWORD 'app-smoke';
GRANT USAGE ON SCHEMA public TO vouchr_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vouchr_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vouchr_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vouchr_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vouchr_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vouchr_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO vouchr_app;
SQL

# Kubernetes `runAsNonRoot` can only verify the IMAGE's declared user (Config.User) when it is a
# non-root NUMERIC uid — a name like `node` cannot be resolved at admission and the pod fails with
# CreateContainerConfigError. Assert the built image actually declares one, so reverting to `USER node`
# fails CI here instead of only at deploy time. (Runtime `id` output is numeric either way, so it
# cannot guard this — inspect the image config.)
IMAGE_USER="$(docker image inspect --format '{{.Config.User}}' "$IMAGE")"
echo "==> image Config.User = '${IMAGE_USER}'"
# Require an exact canonical non-zero numeric uid, optionally :gid. This anchored shape rejects a
# name (`node`), empty, literal `0`/`0:0`, zero-padded root equivalents (`00`, `00:1000`), and
# malformed colon forms — all of which either run as root or cannot be verified by the kubelet.
if ! [[ "$IMAGE_USER" =~ ^[1-9][0-9]*(:[0-9]+)?$ ]]; then
  echo "FAIL: image Config.User must be a canonical non-zero numeric uid (optionally uid:gid); got '${IMAGE_USER}'"; exit 1
fi
echo "    image declares a numeric non-root user"

# The runtime never creates tables (DML-only role, fails closed on an unmigrated DB), so migrate first
# using the SAME image as a separate step with the schema-owner role — the deploy/k8s.yaml Job.
echo "==> migrate the schema as vouchr_owner (separate step, same image)"
docker run --rm --network "$NET" -e VOUCHR_DATABASE_URL="$OWNER_URL" \
  "$IMAGE" node dist/bin/vouchr.js migrate \
  || { echo "FAIL: vouchr migrate errored"; exit 1; }
echo "==> the DML-only runtime role holds no DDL privilege"
if docker exec "$PG_NAME" psql -q -U vouchr_app -d vouchr -c 'CREATE TABLE smoke_ddl_probe ()' >/dev/null 2>&1; then
  echo "FAIL: vouchr_app was able to CREATE TABLE — the runtime role must be DML-only"; exit 1
fi
echo "    vouchr_app cannot CREATE"

# Two stateless replicas, one migrated database, DML-only credentials. The reference manifest pins no
# UID and requires a read-only root filesystem, so replica 2 runs as an ARBITRARY numeric non-root user
# (a Restricted platform assigns one from its range); replica 1 uses the image default. Both read-only.
run_replica() { # N PORT [extra docker run flags]
  local n="$1" port="$2"; shift 2
  docker run -d --name "$NAME-$n" --network "$NET" --read-only --tmpfs /tmp "$@" \
    -e VOUCHR_IDENTITY_SECRET="$SECRET" \
    -e VOUCHR_DEPLOYMENT_ID="$DEPLOYMENT_ID" \
    -e VOUCHR_MASTER_KEY="$MASTER_KEY" \
    -e VOUCHR_PROVIDERS="$PROVIDERS" \
    -e VOUCHR_PORT="$port" \
    -e VOUCHR_DATABASE_URL="$APP_URL" \
    -p "$port:$port" "$IMAGE" >/dev/null
}
echo "==> start two replicas (read-only root; replica 2 as arbitrary uid 12345) on the DML-only role"
run_replica 1 "$PORT1"
run_replica 2 "$PORT2" --user 12345:12345

# Poll /readyz, not /healthz: /healthz is bare liveness (no db), so it can't tell a booted server from
# a usable one. /readyz does a real SELECT 1 through the store, so 200 proves listening AND store-ready.
echo "==> poll /readyz on both replicas until 200 (30s timeout)"
for n in 1 2; do
  port=$PORT1; [ "$n" = 2 ] && port=$PORT2
  ok=""
  for i in $(seq 1 30); do
    if [ "$(code "$port" /readyz)" = 200 ]; then ok=1; echo "    replica $n: /readyz -> 200 after ${i}s"; break; fi
    # If the container died, fail fast with its logs instead of waiting out the timeout.
    running "$NAME-$n" || fail "replica $n exited early"
    sleep 1
  done
  [ -n "$ok" ] || fail "replica $n never returned /readyz 200"
done

echo "==> the startup logs name providers but leak NO secret"
for n in 1 2; do
  LOGS="$(docker logs "$NAME-$n" 2>&1)"
  echo "$LOGS" | grep -q "broker listening" || { echo "FAIL: replica $n has no listening line"; echo "$LOGS"; exit 1; }
  if echo "$LOGS" | grep -qF "$SECRET" || echo "$LOGS" | grep -qF "$MASTER_KEY"; then
    echo "FAIL: a secret value appeared in replica $n's logs"; exit 1
  fi
done
echo "    logs clean of secrets"

# Rolling restart, one replica at a time, as a Deployment rollout does (2 replicas: maxUnavailable 0).
# While replica N is stopped (SIGTERM → drain → exit 0) and restarted, a tight request loop against the
# OTHER replica must see only 200s: through a load balancer that honours /readyz that is zero failed
# requests. The drained process must exit 0 — exit 1 means the VOUCHR_SHUTDOWN_TIMEOUT_MS deadline hit.
echo "==> rolling restart: each replica drains and returns ready while the other serves every request"
roll() { # N PORT OTHER_PORT
  local n="$1" port="$2" other="$3" stop="$TMP/stop-$1" fails="$TMP/fails-$1" count="$TMP/count-$1"
  ( i=0; while [ ! -e "$stop" ]; do [ "$(code "$other" /readyz)" = 200 ] || echo x >>"$fails"; i=$((i + 1)); done; echo "$i" >"$count" ) &
  local loop=$!
  docker stop -t 15 "$NAME-$n" >/dev/null
  [ "$(exit_code "$NAME-$n")" = 0 ] || fail "replica $n did not drain cleanly on SIGTERM (exit $(exit_code "$NAME-$n"))"
  docker start "$NAME-$n" >/dev/null
  wait_code "$port" /readyz 200 30 "replica $n back" || fail "replica $n never became ready after restart"
  touch "$stop"; wait "$loop"
  [ ! -s "$fails" ] || fail "$(wc -l <"$fails" | tr -d ' ') of $(cat "$count") requests failed on the other replica during replica $n's restart"
  echo "    replica $n: drained (exit 0), restarted, ready; $(cat "$count")/$(cat "$count") requests served meanwhile"
}
roll 1 "$PORT1" "$PORT2"
roll 2 "$PORT2" "$PORT1"

# Graceful drain with in-flight work: open a connection, send the headers of a POST whose body has not
# arrived yet, THEN send SIGTERM, then the body. The broker must answer that request (any HTTP status —
# it is a malformed fetch, the point is that it is answered, not reset) and only then exit 0.
echo "==> graceful drain: a request in flight when SIGTERM arrives still gets its response"
exec 3<>"/dev/tcp/127.0.0.1/$PORT1"
printf 'POST /v1/fetch HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n' >&3
docker stop -t 15 "$NAME-1" >/dev/null &
stop_pid=$!
sleep 2 # SIGTERM has been delivered; the request is still in flight (body pending)
printf '{}' >&3
status=""
read -r -t 10 status <&3 || fail "the in-flight request got no response after SIGTERM"
exec 3<&- 3>&-
wait "$stop_pid"
[ "$(exit_code "$NAME-1")" = 0 ] || fail "replica 1 did not exit 0 after draining the in-flight request"
docker logs "$NAME-1" 2>&1 | grep -q "draining connections" || fail "replica 1 logged no drain line on SIGTERM"
echo "    in-flight request answered '$(printf '%s' "$status" | tr -d '\r')' after SIGTERM; process exited 0"
docker start "$NAME-1" >/dev/null
wait_code "$PORT1" /readyz 200 30 "replica 1 back" || fail "replica 1 never became ready after the drain"

# Dependency failure: stop PostgreSQL (the official image's STOPSIGNAL is a fast shutdown). Every
# replica must go not-ready (a load balancer pulls it: requests fail closed instead of reaching a broker
# with no store) while liveness stays green (a DB outage must not restart the fleet). When PostgreSQL
# returns, the pools recover and both replicas are ready again without a restart.
echo "==> dependency failure: PostgreSQL stops -> replicas not-ready but live; PostgreSQL returns -> ready"
docker stop "$PG_NAME" >/dev/null
wait_code "$PORT1" /readyz 503 20 "replica 1" || fail "replica 1 stayed ready without PostgreSQL"
wait_code "$PORT2" /readyz 503 20 "replica 2" || fail "replica 2 stayed ready without PostgreSQL"
for port in "$PORT1" "$PORT2"; do
  [ "$(code "$port" /healthz)" = 200 ] || fail "liveness on :$port failed during the DB outage (would restart the fleet)"
done
echo "    both replicas: /healthz 200 (live) while /readyz 503 (not ready)"
docker start "$PG_NAME" >/dev/null
wait_pg
wait_code "$PORT1" /readyz 200 30 "replica 1 recovered" || fail "replica 1 never recovered after PostgreSQL returned"
wait_code "$PORT2" /readyz 200 30 "replica 2 recovered" || fail "replica 2 never recovered after PostgreSQL returned"
for n in 1 2; do running "$NAME-$n" || fail "replica $n is not running after the outage"; done

echo "==> PASS: image builds; schema-owner migrate + DML-only replicas; 2 replicas ready (default + arbitrary uid, read-only root); logs leak no secret; rolling restart lost 0 requests; in-flight request survived SIGTERM; PostgreSQL outage fails closed and recovers"
