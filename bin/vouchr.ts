#!/usr/bin/env -S node --import tsx
/**
 * vouchr — operator CLI for self-hosted deployments.
 *
 * Connects to the SAME credential store the app uses (SQLite via VOUCHR_DB/--db,
 * or Postgres via VOUCHR_DATABASE_URL) through `openDb`. Read-only, metadata-only:
 * it NEVER decrypts or prints token/secret material. `secret_ref` (an external
 * manager ARN/pointer, non-secret by design) is the only ref it surfaces.
 *
 * Run: `node --import tsx bin/vouchr.ts <cmd>` (or `npm run cli -- <cmd>`).
 */
import { openDb, type Db } from '../src/core/db';
import { loadMasterKey } from '../src/core/crypto';
import { github, google, gitlab, notion, type Provider } from '../src/core/providers';

type Flags = { values: Record<string, string>; positional: string[] };

/** Tiny flag parser: `--key value` / `--key=value` → values; everything else positional. */
function parseFlags(argv: string[]): Flags {
  const values: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) values[a.slice(2, eq)] = a.slice(eq + 1);
      else values[a.slice(2)] = argv[++i] ?? '';
    } else positional.push(a);
  }
  return { values, positional };
}

const ts = (ms: number | null | undefined): string =>
  ms == null ? '-' : new Date(ms).toISOString();

/** Compact left-aligned table. */
function printTable(headers: string[], rows: string[][]): void {
  if (!rows.length) {
    console.log('(none)');
    return;
  }
  const widths = headers.map((h, c) => Math.max(h.length, ...rows.map((r) => (r[c] ?? '').length)));
  const fmt = (cells: string[]) => cells.map((v, c) => (v ?? '').padEnd(widths[c])).join('  ').trimEnd();
  console.log(fmt(headers));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const r of rows) console.log(fmt(r));
}

/** Mirror openDb's backend resolution so `doctor` can report it without opening twice. */
function describeBackend(dbPath?: string): string {
  const url = process.env.VOUCHR_DATABASE_URL ?? process.env.DATABASE_URL;
  if (url && /^postgres(ql)?:\/\//.test(url)) return 'Postgres (VOUCHR_DATABASE_URL)';
  return `SQLite path=${dbPath ?? process.env.VOUCHR_DB ?? 'vouchr.db'}`;
}

async function cmdInventory(db: Db, f: Flags): Promise<void> {
  const where: string[] = [];
  const params: any[] = [];
  if (f.values.team) { where.push('team_id=?'); params.push(f.values.team); }
  if (f.values.provider) { where.push('provider=?'); params.push(f.values.provider); }
  // Metadata columns only — token ciphertext columns are never selected.
  const rows = await db.all<any>(
    `SELECT team_id, owner_kind, owner_id, provider, source, secret_ref, created_at, last_used_at, expires_at
     FROM connection ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY team_id, provider, owner_kind, owner_id`,
    params,
  );
  printTable(
    ['team', 'owner_kind', 'owner_id', 'provider', 'source', 'secret_ref', 'created_at', 'last_used_at', 'expires_at'],
    rows.map((r) => [
      r.team_id, r.owner_kind, r.owner_id, r.provider, r.source,
      r.secret_ref ?? '-', ts(r.created_at), ts(r.last_used_at), ts(r.expires_at),
    ]),
  );
}

async function cmdChannels(db: Db, f: Flags): Promise<void> {
  // FULL OUTER JOIN: a channel may have a config row, a tool row, or both.
  // Supported by Postgres and by the SQLite bundled with better-sqlite3 (>=3.39).
  const where = f.values.team ? 'WHERE COALESCE(c.team_id, t.team_id)=?' : '';
  const params = f.values.team ? [f.values.team] : [];
  const rows = await db.all<any>(
    `SELECT COALESCE(c.team_id, t.team_id)   AS team_id,
            COALESCE(c.channel, t.channel)   AS channel,
            COALESCE(c.provider, t.provider) AS provider,
            c.mode    AS mode,
            t.enabled AS enabled
     FROM channel_config c
     FULL OUTER JOIN channel_tool t
       ON c.team_id=t.team_id AND c.channel=t.channel AND c.provider=t.provider
     ${where}
     ORDER BY team_id, channel, provider`,
    params,
  );
  printTable(
    ['team', 'channel', 'provider', 'mode', 'enabled'],
    rows.map((r) => [
      r.team_id, r.channel, r.provider,
      r.mode ?? '-',
      r.enabled == null ? '-' : r.enabled ? 'yes' : 'no',
    ]),
  );
}

async function cmdDoctor(f: Flags): Promise<number> {
  let failed = false;
  const pass = (label: string, msg = '') => console.log(`PASS ${label}${msg ? ' — ' + msg : ''}`);
  const fail = (label: string, msg = '') => { failed = true; console.log(`FAIL ${label}${msg ? ' — ' + msg : ''}`); };

  // 1. Master key — load via loadMasterKey, never print the key itself.
  try {
    const len = loadMasterKey().length;
    len === 32 ? pass('master key', '32 bytes') : fail('master key', `decoded ${len} bytes (want 32)`);
  } catch (e: any) {
    fail('master key', e?.message ?? 'invalid');
  }

  // 2. Backend in use (informational).
  console.log(`INFO backend — ${describeBackend(f.values.db)}`);

  // 3. DB reachable + counts.
  let db: Db | undefined;
  try {
    db = await openDb({ dbPath: f.values.db });
    await db.get('SELECT 1 AS x');
    pass('db reachable');
    const conns = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM connection');
    const consents = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM consent_request');
    console.log(`INFO connections — ${conns?.n ?? 0}`);
    console.log(`INFO consent_requests — ${consents?.n ?? 0}`);
  } catch (e: any) {
    fail('db reachable', e?.message ?? 'open failed');
  } finally {
    await db?.close();
  }

  return failed ? 1 : 0;
}

/** Best-effort: any HTTP response (even 4xx/5xx) means the host is reachable. */
async function reachable(host: string, timeoutMs = 5000): Promise<boolean> {
  try {
    await fetch(`https://${host}/`, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    return true;
  } catch {
    return false;
  }
}

// Built-in providers. Dummy creds satisfy defineProvider's clientId/clientSecret check;
// health only reads authorizeUrl/tokenUrl hosts and never sends credentials.
const BUILTINS: Record<string, () => Provider> = {
  github: () => github({ clientId: 'x', clientSecret: 'x' }),
  google: () => google({ clientId: 'x', clientSecret: 'x' }),
  gitlab: () => gitlab({ clientId: 'x', clientSecret: 'x' }),
  notion: () => notion({ clientId: 'x', clientSecret: 'x' }),
};

async function cmdHealth(f: Flags): Promise<void> {
  // Each target → a label and the set of hosts to probe.
  const targets: { label: string; hosts: string[] }[] = [];
  const names = f.positional.length ? f.positional : Object.keys(BUILTINS);
  for (const name of names) {
    if (BUILTINS[name]) {
      const p = BUILTINS[name]();
      const hosts = [...new Set([new URL(p.authorizeUrl).host, new URL(p.tokenUrl).host])];
      targets.push({ label: name, hosts });
    } else {
      // Treat an unrecognised arg as a bare hostname to probe directly.
      targets.push({ label: name, hosts: [name] });
    }
  }
  const rows: string[][] = [];
  for (const t of targets) {
    for (const host of t.hosts) {
      const ok = await reachable(host);
      rows.push([t.label, host, ok ? 'reachable' : 'unreachable']);
    }
  }
  printTable(['target', 'host', 'status'], rows);
}

function usage(): void {
  console.log(`vouchr — operator CLI (read-only, secret-free)

Usage: vouchr <command> [options]

Commands:
  inventory   List stored connections (metadata only; never tokens).
                --team <id>      filter by team
                --provider <id>  filter by provider
  channels    List per-channel config: team, channel, provider, mode, enabled.
                --team <id>      filter by team
  doctor      Diagnostics (PASS/FAIL): master key, DB reachability, row counts.
                exits non-zero if any check fails
  health [provider|host ...]
              Reachability of provider authorize/token hosts (no credentials sent).
              Defaults to built-ins: ${Object.keys(BUILTINS).join(', ')}.
  help        This message.

Store selection (shared with the app):
  --db <path>            SQLite file (overrides VOUCHR_DB; default vouchr.db)
  VOUCHR_DB              SQLite file path
  VOUCHR_DATABASE_URL    Postgres connection string (takes precedence)
  VOUCHR_MASTER_KEY      base64 32-byte key (only loaded/validated by doctor)`);
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  const f = parseFlags(rest);

  switch (cmd) {
    case 'inventory':
    case 'channels': {
      const db = await openDb({ dbPath: f.values.db });
      try {
        if (cmd === 'inventory') await cmdInventory(db, f);
        else await cmdChannels(db, f);
      } finally {
        await db.close();
      }
      return 0;
    }
    case 'doctor':
      return cmdDoctor(f);
    case 'health':
      await cmdHealth(f);
      return 0;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      usage();
      return 0;
    default:
      console.error(`Unknown command: ${cmd}\n`);
      usage();
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error(`vouchr: ${e?.message ?? e}`);
    process.exit(1);
  });
