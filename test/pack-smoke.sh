#!/usr/bin/env bash
# Packaging smoke test (#123): pack the real tarball, install it into a fresh throwaway
# project, and prove every published entrypoint / bin / type actually resolves — the way the
# pilot integrator's first `npm install` will. Catches a broken `files` glob, an `exports`
# typo, a bad bin shebang, or a type regression that `tsc` on src/ never sees.
#
# Runnable locally (`npm run pack-smoke`) and in CI. Needs network for the consumer install.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> npm pack (runs prepack → build)"
# npm pack prints noise to stdout; capture only the tarball filename it reports last.
( cd "$ROOT" && npm pack --pack-destination "$WORK" >/dev/null )
TGZ="$(ls "$WORK"/vouchr-core-*.tgz)"
[ -f "$TGZ" ] || { echo "FAIL: no tarball produced"; exit 1; }
echo "    packed: $(basename "$TGZ")"

echo "==> install into a fresh consumer project"
CONSUMER="$WORK/consumer"
mkdir -p "$CONSUMER"
( cd "$CONSUMER" && npm init -y >/dev/null && npm install "$TGZ" >/dev/null )

echo "==> require() every published entrypoint (CJS exports map)"
( cd "$CONSUMER" && node -e "
  require('@vouchr/core');
  require('@vouchr/core/headless');
  require('@vouchr/core/broker-server');
  console.log('    all three entrypoints require() cleanly');
" )

echo "==> every bin resolves and prints on --help"
for bin in vouchr vouchr-broker vouchr-seed; do
  out="$( cd "$CONSUMER" && npx --no-install "$bin" --help 2>&1 )" || {
    echo "FAIL: $bin --help exited non-zero"; echo "$out"; exit 1;
  }
  [ -n "$out" ] || { echo "FAIL: $bin --help printed nothing"; exit 1; }
  echo "    $bin --help ok"
done

echo "==> a minimal typed consumer compiles against the published types"
cat > "$CONSUMER/consumer.ts" <<'TS'
import { createVouchr } from '@vouchr/core';
import { createBroker, signIdentity, type BrokerFetchResponse } from '@vouchr/core/headless';

// Type-level only — never executed. Proves the type entrypoints resolve and the shapes exist.
export function _smoke(r: BrokerFetchResponse): number {
  void createVouchr;
  void createBroker;
  void signIdentity;
  return r.status;
}
TS
cat > "$CONSUMER/tsconfig.json" <<'JSON'
{
  "compilerOptions": {
    "module": "nodenext",
    "moduleResolution": "nodenext",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true
  },
  "files": ["consumer.ts"]
}
JSON
( cd "$CONSUMER" && npm install -D typescript@5 >/dev/null && npx tsc -p tsconfig.json )
echo "    typed consumer compiles"

echo "==> PASS: package installs, resolves, and type-checks"
