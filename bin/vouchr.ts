#!/usr/bin/env node
/**
 * vouchr: operator CLI for self-hosted deployments.
 *
 * Connects to the SAME credential store the app uses (PostgreSQL via
 * VOUCHR_DATABASE_URL or --db) through `openDb`. The read commands
 * (inventory/channels/doctor) are metadata-only and NEVER decrypt or print
 * token/secret material. Four commands mutate: `migrate` creates/alters the schema;
 * `revoke` DELETES credential rows and may best-effort decrypt an access token to hand
 * to the upstream revoke — never to stdout; `rekey` re-encrypts ciphertext columns under
 * the primary master key and prints counts only; `prune` DELETES old `audit` rows
 * (retention, #208). `revoke` and `prune` are dry-run by default and require an exact
 * bare `--yes` to delete.
 * Caller-controlled reference/source values are never selected or printed; inventory exposes only
 * a reference-presence marker and an allowlisted built-in source kind (otherwise `custom`).
 *
 * Run: `node --import tsx bin/vouchr.ts <cmd>` (or `npm run cli -- <cmd>`).
 */
import { parseArgs, type ParseArgsOptionsConfig } from 'node:util';
import { openDb, migrate, type Db } from '../src/core/db';
import { loadKeyring, type EnvelopeProvider, type Keyring } from '../src/core/crypto';
import { rekey } from '../src/core/rekey';
import { isPostgresUrl } from '../src/core/options';
import { isValidProviderId, ProviderRegistry } from '../src/core/providers';
import { Vault } from '../src/core/vault';
import { Audit, MAX_AUDIT_PRUNE_BATCH } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { SECRET_REFERENCE_SOURCES } from '../src/core/reference';
import {
  selectRevocations,
  revokeConnection,
  countPendingForProvider,
  purgePendingForProvider,
  revokeAllCredentials,
  type RevokeFilter,
  type RevokeAllReport,
  type RevokeCategory,
} from '../src/core/offboard';
import { loadProviders } from './providerConfig';

/** The flags the NON-destructive commands accept, parsed per command by {@link READ_SPECS}. */
type Flags = { db?: string; team?: string; provider?: string; 'dry-run'?: boolean };

/**
 * Per-command flag sets for the non-destructive commands, parsed by `node:util.parseArgs` in STRICT
 * mode: an unknown flag, a positional, a valued boolean (`--dry-run=x`), and a missing or
 * flag-shaped value (the `vouchr rekey --db --dry-run` typo, which must never silently become a
 * live rekey) are usage errors instead of being absorbed. The DESTRUCTIVE commands keep
 * {@link strictParse}, which additionally rejects duplicate flags and empty values — neither is
 * expressible with parseArgs.
 */
const READ_SPECS: Record<string, ParseArgsOptionsConfig> = {
  migrate: { db: { type: 'string' } },
  inventory: { db: { type: 'string' }, team: { type: 'string' }, provider: { type: 'string' } },
  channels: { db: { type: 'string' }, team: { type: 'string' } },
  rekey: { db: { type: 'string' }, 'dry-run': { type: 'boolean' } },
  doctor: { db: { type: 'string' } },
};

type FlagSpec = Record<string, 'string' | 'boolean'>;
type StrictValues = Record<string, string | true>;

/**
 * Strict CLI parse for the DESTRUCTIVE commands (`revoke`, `prune`). It rejects: an unknown
 * flag, a positional argument, a duplicate flag, a boolean flag given a value (`--yes=…`), and a
 * value flag missing its value or given a flag-shaped one (the `--team --yes` typo). Consequently a
 * confirmed delete requires an EXACT bare `--yes`. Runs BEFORE the database is opened.
 *
 * Not `node:util.parseArgs` (which the read commands use, see {@link READ_SPECS}): parseArgs is
 * last-writer-wins on a duplicate flag and accepts an empty value, so `--team=` would silently mean
 * "no filter" and widen a delete. Those two rules are the reason this parser exists.
 */
function strictParse(argv: string[], spec: FlagSpec): { values: StrictValues } | { error: string } {
  // SEC-1: error messages NEVER echo an argument value or an unknown flag name — a positional or an
  // unknown flag could be token-shaped or a credential-bearing URL. Only canonical spec flag names
  // (safe by construction) appear in messages.
  const allowed = () => Object.keys(spec).map((k) => `--${k}`).join(', ');
  const values: StrictValues = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) return { error: `unexpected positional argument (only flags are allowed: ${allowed()})` };
    const eq = a.indexOf('=');
    const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
    const inline = eq === -1 ? undefined : a.slice(eq + 1);
    const type = spec[name];
    if (!type) return { error: `unknown flag (allowed: ${allowed()})` }; // never echo the unknown name
    if (name in values) return { error: `--${name} given more than once` };
    if (type === 'boolean') {
      if (inline !== undefined) return { error: `--${name} takes no value (pass a bare --${name})` };
      values[name] = true;
    } else {
      // A value flag: inline `--k=v`, else the next token (which must not be a flag). Empty/whitespace
      // is rejected — an empty scope (`--team=`) would otherwise mean "no filter" and widen a delete.
      let val: string;
      if (inline !== undefined) val = inline;
      else {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith('--')) return { error: `--${name} requires a value` };
        val = next;
        i++;
      }
      if (val.trim() === '') return { error: `--${name} requires a non-empty value` };
      values[name] = val;
    }
  }
  return { values };
}

/**
 * Exact destructive confirmation for `revoke`/`prune`, over strictly-parsed values (so `--yes` is
 * already guaranteed bare — a valued form was rejected upstream). Returns 'go' only for a bare
 * `--yes`; 'dry-run' otherwise; an `{ error }` when `--yes` and `--dry-run` conflict.
 */
function destructiveIntent(v: StrictValues): 'go' | 'dry-run' | { error: string } {
  if (v.yes === true && v['dry-run'] === true) return { error: '--yes and --dry-run are mutually exclusive' };
  return v.yes === true ? 'go' : 'dry-run';
}

const REVOKE_SPEC: FlagSpec = { db: 'string', provider: 'string', team: 'string', user: 'string', channel: 'string', all: 'boolean', confirm: 'string', yes: 'boolean', 'dry-run': 'boolean' };
const PRUNE_SPEC: FlagSpec = { db: 'string', 'older-than-days': 'string', batch: 'string', yes: 'boolean', 'dry-run': 'boolean' };

/** The exact confirmation token a deployment-wide revoke requires — stronger than the surgical
 *  path's bare `--yes` (#239: global execution must be intentionally difficult to trigger). */
const REVOKE_ALL_CONFIRMATION = 'ALL-CREDENTIALS';

type RevokePlan =
  | { mode: 'provider'; db?: string; filter: RevokeFilter; dryRun: boolean }
  | { mode: 'all'; db?: string; execute: boolean };

/** Validate revoke's arguments BEFORE any DB opens so invalid usage exits 2 even if Postgres is
 *  unreachable. Two shapes: the surgical provider-scoped path (`--provider` required, exact-bare
 *  `--yes`) and the deployment-wide `--all` path (no owner scope; `--confirm ALL-CREDENTIALS`). */
function planRevoke(v: StrictValues): RevokePlan | { error: string } {
  if (v.all === true) {
    // `--all` is the deployment-wide scope. It must not be narrowed (that would contradict "all")
    // and uses its own stronger confirmation instead of `--yes`.
    if (v.provider !== undefined) return { error: '--all revokes every provider; do not combine it with --provider' };
    if (v.team !== undefined || v.user !== undefined || v.channel !== undefined) {
      return { error: '--all takes no owner scope; it revokes every credential in the store' };
    }
    if (v.yes === true) return { error: `--all requires --confirm ${REVOKE_ALL_CONFIRMATION} (not --yes)` };
    const confirm = v.confirm as string | undefined;
    if (confirm === undefined) return { mode: 'all', db: v.db as string | undefined, execute: false };
    if (v['dry-run'] === true) return { error: '--confirm and --dry-run are mutually exclusive' };
    if (confirm !== REVOKE_ALL_CONFIRMATION) {
      return { error: `--confirm must be exactly ${REVOKE_ALL_CONFIRMATION} to revoke every credential` };
    }
    return { mode: 'all', db: v.db as string | undefined, execute: true };
  }
  if (v.confirm !== undefined) return { error: `--confirm is only valid with --all (use --yes for a --provider revoke)` };
  const provider = v.provider as string | undefined;
  if (!provider) return { error: '--provider <id> is required (refusing to revoke across every provider); use --all --confirm ' + REVOKE_ALL_CONFIRMATION + ' for a deployment-wide revoke' };
  if (!isValidProviderId(provider)) return { error: '--provider must be a valid provider id' };
  if (v.user !== undefined && v.channel !== undefined) {
    return { error: '--user and --channel are mutually exclusive owner scopes' };
  }
  const intent = destructiveIntent(v);
  if (typeof intent === 'object') return intent;
  return {
    mode: 'provider',
    db: v.db as string | undefined,
    filter: { provider, teamId: v.team as string | undefined, userId: v.user as string | undefined, channel: v.channel as string | undefined },
    dryRun: intent === 'dry-run',
  };
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
function describeBackend(dbUrl?: string): string {
  const url = dbUrl ?? process.env.VOUCHR_DATABASE_URL; // no generic DATABASE_URL fallback (#204)
  return isPostgresUrl(url) ? 'PostgreSQL' : 'PostgreSQL (not configured — set VOUCHR_DATABASE_URL)';
}

async function cmdInventory(db: Db, f: Flags): Promise<void> {
  const where: string[] = [];
  const params: any[] = [];
  if (f.team) { where.push('team_id=?'); params.push(f.team); }
  if (f.provider) { where.push('provider=?'); params.push(f.provider); }
  const sourcePlaceholders = SECRET_REFERENCE_SOURCES.map(() => '?').join(', ');
  // Metadata columns only. Neither token ciphertext nor raw reference/source values are selected:
  // legacy rows can predate validation, so even fields intended as metadata are untrusted output.
  const rows = await db.all<any>(
    `SELECT team_id, owner_kind, owner_id, provider,
            CASE WHEN source IN (${sourcePlaceholders}) THEN source ELSE 'custom' END AS source_kind,
            (secret_ref IS NOT NULL) AS has_reference, created_at, last_used_at, expires_at
     FROM connection ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY team_id, provider, owner_kind, owner_id`,
    [...SECRET_REFERENCE_SOURCES, ...params],
  );
  printTable(
    ['team', 'owner_kind', 'owner_id', 'provider', 'source', 'reference', 'created_at', 'last_used_at', 'expires_at'],
    rows.map((r) => [
      r.team_id, r.owner_kind, r.owner_id, r.provider, r.source_kind,
      r.has_reference ? 'yes' : 'no', ts(r.created_at), ts(r.last_used_at), ts(r.expires_at),
    ]),
  );
}

async function cmdChannels(db: Db, f: Flags): Promise<void> {
  // FULL OUTER JOIN: a channel may have a config row, a tool row, or both.
  const where = f.team ? 'WHERE COALESCE(c.team_id, t.team_id)=?' : '';
  const params = f.team ? [f.team] : [];
  const rows = await db.all<any>(
    `SELECT COALESCE(c.team_id, t.team_id)   AS team_id,
            COALESCE(c.channel, t.channel)   AS channel,
            COALESCE(c.provider, t.provider) AS provider,
            c.identity AS identity,
            t.enabled AS enabled
     FROM channel_config c
     FULL OUTER JOIN channel_tool t
       ON c.team_id=t.team_id AND c.channel=t.channel AND c.provider=t.provider
     ${where}
     ORDER BY team_id, channel, provider`,
    params,
  );
  printTable(
    ['team', 'channel', 'provider', 'identity', 'enabled'],
    rows.map((r) => [
      r.team_id, r.channel, r.provider,
      r.identity ?? 'person',
      r.enabled == null ? '-' : r.enabled ? 'yes' : 'no',
    ]),
  );
}

/**
 * Break-glass bulk revocation: kill every stored credential for a provider (optionally narrowed to a
 * team/user/channel) during incident response. Dry-run is the DEFAULT — it prints a no-secret table
 * and mutates nothing; `--yes` is required to actually revoke. Refuses to run without `--provider`.
 *
 * Local deletion is the security-meaningful action and MUST be guaranteed: the provider registry and
 * master key (needed only for the best-effort UPSTREAM revoke + token decrypt) are loaded defensively,
 * so a malformed provider config or an unavailable master key disables upstream revoke but never blocks
 * the local kill. It never PRINTS a secret; the only decryption is the just-read access token handed to
 * the upstream revoke, never to stdout. Pending consent/key-setup authority is cleared too.
 */
async function cmdRevoke(db: Db, plan: Extract<RevokePlan, { mode: 'provider' }>): Promise<number> {
  const { filter, dryRun } = plan;
  const rows = await selectRevocations(db, filter);
  // SEC-1: scope values came directly from argv and may be credential-shaped. Report which canonical
  // filters were applied, never their raw values; matched stored metadata is shown in the table below.
  const scope = ['provider', filter.teamId && 'team', filter.userId && 'user', filter.channel && 'channel'].filter(Boolean).join('+');
  console.log(`${dryRun ? 'DRY-RUN' : 'REVOKE'} ${scope}: ${rows.length} connection(s)`);
  printTable(
    ['team', 'owner_kind', 'owner', 'external_account', 'created_at'],
    rows.map((r) => [r.teamId, r.ownerKind, r.ownerId, r.externalAccount ?? '-', ts(r.createdAt)]),
  );
  if (dryRun) {
    const pending = await countPendingForProvider(db, filter);
    if (pending.consents || pending.provisioning || pending.channelProvisioning) {
      console.log(
        `Would also clear ${pending.consents} pending consent + ${pending.provisioning} user setup request(s) + ` +
        `${pending.channelProvisioning} channel setup request(s).`,
      );
    }
    if (rows.length || pending.consents || pending.provisioning || pending.channelProvisioning) {
      console.log('\nNo changes made. Re-run with --yes to revoke.');
    }
    return 0;
  }

  // Load the registry + master key BEST-EFFORT: break-glass must not die before the local delete just
  // because provider config is malformed or the key is missing. A failure only disables upstream revoke
  // (and token decrypt); the local delete below needs neither the key nor the registry.
  let registry: ProviderRegistry | undefined;
  try {
    registry = new ProviderRegistry(loadProviders(process.env));
  } catch {
    console.error('revoke: provider config unavailable; upstream revoke disabled — local deletion will proceed');
  }
  // Establish the scoped provisioning fence and clear pending authority BEFORE deleting live rows.
  // A matching old writer either committed before this marker and appears in the scan below, or it
  // observes the marker and refuses. Registry membership validates a provider with no stored rows;
  // a retired provider is recognized from its exact durable state inside the core helper.
  const purged = await purgePendingForProvider(db, filter, {
    providerRegistered: registry?.has(filter.provider) ?? false,
  });

  let key: Buffer | Keyring;
  try {
    key = loadKeyring(); // full ring, so post-rotation rows (keyed scheme) still decrypt for upstream revoke
  } catch {
    console.error('revoke: master key unavailable; token decrypt + upstream revoke disabled — local deletion will proceed');
    key = Buffer.alloc(32); // never used to decrypt successfully; vault.delete needs no key
  }
  const vault = new Vault(db, key, {}, await loadRevokeEnvelope());
  const audit = new Audit(db);
  const consent = new Consent(db);

  let localRemoved = 0;
  let upstreamAttempted = 0;
  let upstreamFailures = 0;
  let upstreamUnresolved = 0;
  let upstreamSkipped = 0;
  const revokeRows = async (batch: typeof rows) => {
    for (const row of batch) {
      // revokeConnection is best-effort internally, but keep a backstop so an unexpected throw on
      // one row never strands the rest of a break-glass sweep.
      try {
        const r = await revokeConnection(vault, audit, consent, registry, row, filter.provider);
        if (r.removed) {
          localRemoved++;
          if (r.upstreamAttempted) {
            upstreamAttempted++;
            if (r.upstreamUnreadable || r.upstreamMissing) upstreamUnresolved++;
            else if (!r.upstreamOk) upstreamFailures++;
          }
          else if (row.source !== 'vault' || row.hasReference || r.upstreamOk) upstreamSkipped++;
          else upstreamUnresolved++;
        }
      } catch {
        // A provider/KMS extension may include credential material in a thrown value. Keep the
        // break-glass sweep moving, but never serialize that value (SEC-1).
        console.error('revoke: one connection failed; continuing');
      }
    }
  };
  // Re-select after the fence: a pre-fence writer that owned its scope lock was allowed to finish,
  // and is now a normal visible row that this same command must remove.
  await revokeRows(await selectRevocations(db, filter));
  const settledRows = await selectRevocations(db, filter);
  if (settledRows.length) await revokeRows(settledRows);
  const remaining = await selectRevocations(db, filter);
  console.log(`\nRevoked ${localRemoved} locally; ${remaining.length} matching connection(s) remain.`);
  // Report upstream honestly: unsupported/external/synthetic skips differ from required token
  // material that could not be read or was absent. Neither is upstream success.
  console.log(
    `Upstream revoke: ${upstreamAttempted} attempted (${upstreamFailures} failed), ` +
    `${upstreamUnresolved} unresolved (required token unavailable), ${upstreamSkipped} skipped ` +
    '(unsupported provider, external reference, or synthetic row).',
  );
  console.log(
    `Cleared ${purged.consents} pending consent + ${purged.provisioning} user setup request(s) + ` +
    `${purged.channelProvisioning} channel setup request(s).`,
  );
  // Non-zero only when local access remains; upstream failures do not fail the local kill.
  return remaining.length ? 1 : 0;
}

/** Best-effort KMS wiring for upstream revoke. The local delete never depends on this; an SDK,
 * credential, KMS, or network failure only moves affected rows into the undecryptable bucket. */
async function loadRevokeEnvelope(): Promise<EnvelopeProvider | undefined> {
  const keyId = process.env.VOUCHR_KMS_KEY_ID;
  if (!keyId) return undefined;
  try {
    const { kmsEnvelope, awsKmsClient } = await import('../src/adapters/kms.js');
    return kmsEnvelope(keyId, await awsKmsClient({ region: process.env.AWS_REGION }));
  } catch {
    console.error('revoke: KMS unavailable; envelope token decrypt + upstream revoke disabled — local deletion will proceed');
    return undefined;
  }
}

/** Print a {@link RevokeAllReport} — safe counts and registry-trusted provider ids only (SEC-1). */
function printRevokeAllReport(report: RevokeAllReport): void {
  const cat = (c: RevokeCategory): number => report.upstream[c];
  if (!report.executed) {
    console.log(`DRY-RUN revoke --all: ${report.matched.connections} connection(s) across ${report.providerCount} provider(s).`);
    console.log(
      `  would attempt upstream revoke: ${cat('would_attempt')}; external reference (rotate in source manager): ${cat('external_reference')}; ` +
      `no upstream revoke available: ${cat('unsupported')}; synthetic/dry-run: ${cat('synthetic')}.`,
    );
    if (report.byProvider.length || report.unregistered.providers) {
      printTable(
        ['provider', 'connections', 'would_attempt', 'unsupported', 'external', 'synthetic'],
        [
          ...report.byProvider.map((p) => [
            p.provider, String(p.connections), String(p.upstream.would_attempt),
            String(p.upstream.unsupported), String(p.upstream.external_reference), String(p.upstream.synthetic),
          ]),
          ...(report.unregistered.providers ? [[
            `unregistered (${report.unregistered.providers})`, String(report.unregistered.connections),
            String(report.unregistered.upstream.would_attempt), String(report.unregistered.upstream.unsupported),
            String(report.unregistered.upstream.external_reference), String(report.unregistered.upstream.synthetic),
          ]] : []),
        ],
      );
    }
    const m = report.matched;
    console.log(
      `Would also clear ${m.consents} pending consent + ${m.approvals} approval(s) + ` +
      `${m.userProvisioning} user setup + ${m.channelProvisioning} channel setup request(s) + ` +
      `${m.notifications} notification state row(s), and invalidate ${m.installations} Slack installation(s).`,
    );
    console.log(`\nNo changes made. Re-run with --confirm ${REVOKE_ALL_CONFIRMATION} to revoke every credential.`);
    return;
  }
  console.log(`REVOKE --all: ${report.matched.connections} connection(s) across ${report.providerCount} provider(s).`);
  console.log(`Locally removed ${report.removedLocal} connection(s) via the per-provider sweep.`);
  console.log(
    `Upstream: ${report.upstreamAttempted} attempted; ${cat('revoked')} revoked, ` +
    `${cat('revoke_failed')} failed (incl. timeouts), ` +
    `${cat('unsupported')} unsupported (no revoke endpoint / unregistered provider), ` +
    `${cat('undecryptable')} undecryptable (token unreadable — upstream NOT revoked), ` +
    `${cat('unresolved')} unresolved (claim/required token unavailable), ` +
    `${cat('external_reference')} external reference (rotate in the source manager), ` +
    `${cat('synthetic')} synthetic.`,
  );
  if (report.byProvider.length || report.unregistered.providers) {
    printTable(
      ['provider', 'connections', 'attempted', 'revoked', 'failed', 'unsupported', 'undecryptable', 'unresolved', 'external', 'synthetic'],
      [
        ...report.byProvider.map((p) => [
          p.provider, String(p.connections), String(p.attempted), String(p.upstream.revoked), String(p.upstream.revoke_failed),
          String(p.upstream.unsupported), String(p.upstream.undecryptable), String(p.upstream.unresolved),
          String(p.upstream.external_reference), String(p.upstream.synthetic),
        ]),
        ...(report.unregistered.providers ? [[
          `unregistered (${report.unregistered.providers})`, String(report.unregistered.connections),
          String(report.unregistered.attempted), String(report.unregistered.upstream.revoked),
          String(report.unregistered.upstream.revoke_failed),
          String(report.unregistered.upstream.unsupported), String(report.unregistered.upstream.undecryptable),
          String(report.unregistered.upstream.unresolved), String(report.unregistered.upstream.external_reference),
          String(report.unregistered.upstream.synthetic),
        ]] : []),
      ],
    );
  }
  const c = report.cleared;
  const bad = (n: number) => (n < 0 ? 'FAILED' : String(n));
  console.log(
    `Purged locally: ${bad(c.connections)} connection(s), ${bad(c.consents)} consent(s), ` +
    `${bad(c.approvals)} approval(s), ${bad(c.userProvisioning)} user setup, ` +
    `${bad(c.channelProvisioning)} channel setup, ${bad(c.notifications)} notification state, ${bad(c.installations)} Slack installation(s).`,
  );
  console.log(
    `\nLocal invalidation is complete when 0 remain: ${report.remaining.credentials} credential(s), ` +
    `${report.remaining.authorizations} authorization row(s), ${report.remaining.installations} installation(s) remain.`,
  );
  // Residual-exposure honesty (#239): never claim deleting ciphertext kills an already-copied bearer.
  console.log(
    'NOTE: local deletion does not revoke a token an attacker already copied. Vouchr follows each configured ' +
    'provider\'s access/refresh/both/grant revoke contract, but any access/refresh token ' +
    'exfiltrated before this run stays valid at the provider until it expires or is rotated. Providers ' +
    'without a revoke endpoint, undecryptable tokens, and external references require MANUAL rotation. ' +
    'Invalidated Slack installations require each workspace to reinstall the app. Rotate master keys, ' +
    'OAuth client secrets, and Slack credentials, and require users/admins to reconnect, before serving again.',
  );
}

/**
 * Deployment-wide emergency invalidation (#239): kill EVERY stored credential + authorization path
 * for a compromise of the Vouchr database/decryption boundary itself. Dry-run by default; execution
 * needs the exact `--confirm ALL-CREDENTIALS`. Local deletion is guaranteed even with the master key
 * or provider config unavailable (they gate only the best-effort upstream revoke). Never prints a
 * secret. Exits non-zero if any local credential/authorization row remains.
 */
async function cmdRevokeAll(db: Db, execute: boolean): Promise<number> {
  let registry: ProviderRegistry | undefined;
  try {
    registry = new ProviderRegistry(loadProviders(process.env));
  } catch {
    console.error('revoke: provider config unavailable; upstream revoke disabled — local deletion will proceed');
  }
  let key: Buffer | Keyring;
  try {
    key = loadKeyring();
  } catch {
    console.error('revoke: master key unavailable; token decrypt + upstream revoke disabled — local deletion will proceed');
    key = Buffer.alloc(32); // never decrypts successfully; the local delete needs no key
  }
  // The operator CLI is NOT lockdown-gated: break-glass must work during an incident (it deletes and
  // never serves), so this Vault is constructed without the VOUCHR_LOCKDOWN flag.
  const deps = {
    vault: new Vault(db, key, {}, execute ? await loadRevokeEnvelope() : undefined),
    audit: new Audit(db),
    registry,
  };
  const report = await revokeAllCredentials(db, deps, { execute });
  printRevokeAllReport(report);
  return report.executed ? (report.ok ? 0 : 1) : 0;
}

/**
 * Master-key rotation (#115): re-encrypt every stored ciphertext under the PRIMARY key (the first
 * `VOUCHR_MASTER_KEYS` entry). All logic lives in core (`src/core/rekey.ts`); this prints counts
 * only — never key material, plaintext, or ciphertext (SEC-1). `--dry-run` classifies and counts
 * per key-id/scheme without writing, which is also the runbook's "zero old-key rows" check.
 */
async function cmdRekey(db: Db, f: Flags): Promise<number> {
  let ring: Keyring;
  try {
    ring = loadKeyring();
  } catch {
    console.error('rekey: master key configuration is invalid — set VOUCHR_MASTER_KEYS to id:base64key entries (first = primary)');
    return 2;
  }
  const dryRun = f['dry-run'] === true;
  const primary = ring.primary.id === null ? 'id-less VOUCHR_MASTER_KEY' : `key '${ring.primary.id}'`;
  console.log(`${dryRun ? 'REKEY DRY-RUN' : 'REKEY'}: re-encrypt under ${primary} (${ring.legacy.length} key(s) configured)`);
  const r = await rekey(db, ring, {
    dryRun,
    onProgress: (table, done, total) => console.log(`  ${table}: ${done}/${total} row(s)`),
  });
  console.log('');
  printTable(
    ['decrypt source', 'blobs'],
    Object.entries(r.bySource).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, String(v)]),
  );
  console.log(`\nalready under primary: ${r.alreadyPrimary}`);
  console.log(`${dryRun ? 'would re-encrypt' : 're-encrypted'}: ${r.reencrypted}`);
  console.log(`envelope (KMS-managed, skipped): ${r.envelope}`);
  if (r.skippedConcurrent) console.log(`skipped (written concurrently; re-run to converge): ${r.skippedConcurrent}`);
  console.log(`unreadable under configured keys: ${r.unreadable}`);
  if (dryRun) console.log('\nNo changes made. Re-run without --dry-run to re-encrypt.');
  if (r.unreadable) {
    const ids = r.unknownKeyIds.length ? ` Missing key id(s): ${r.unknownKeyIds.map((i) => `'${i}'`).join(', ')}.` : '';
    console.error(`\nrekey: ${r.unreadable} blob(s) decrypt under NO configured key.${ids} Add the missing key(s) to VOUCHR_MASTER_KEYS and re-run.`);
    return 1;
  }
  return 0;
}

async function cmdDoctor(f: Flags): Promise<number> {
  let failed = false;
  const pass = (label: string, msg = '') => console.log(`PASS ${label}${msg ? ': ' + msg : ''}`);
  const fail = (label: string, msg = '') => { failed = true; console.log(`FAIL ${label}${msg ? ': ' + msg : ''}`); };

  // 1. Master key(s): load via loadKeyring, never print key material itself.
  try {
    const ring = loadKeyring();
    // Single id-less key → today's exact output (UX-2); a keyring reports count + primary id.
    if (ring.primary.id === null && ring.legacy.length === 1) pass('master key', '32 bytes');
    else pass('master key', `${ring.legacy.length} keys; new writes under '${ring.primary.id}'`);
  } catch {
    fail('master key', 'invalid — set VOUCHR_MASTER_KEY (openssl rand -base64 32) or VOUCHR_MASTER_KEYS');
  }

  // 2. Backend in use (informational).
  console.log(`INFO backend: ${describeBackend(f.db)}`);

  // 3. DB reachable + counts.
  let db: Db | undefined;
  try {
    db = await openDb({ databaseUrl: f.db });
    await db.get('SELECT 1 AS x');
    pass('db reachable');
    const conns = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM connection');
    const consents = await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM consent_request');
    console.log(`INFO connections: ${conns?.n ?? 0}`);
    console.log(`INFO consent_requests: ${consents?.n ?? 0}`);
  } catch {
    fail('db reachable', 'open failed');
  } finally {
    await db?.close();
  }

  return failed ? 1 : 0;
}

type PrunePlan = { cutoff: number; batch: number; dryRun: boolean };

/**
 * Validate prune's arguments BEFORE any DB is opened (#208): a positive-integer `--older-than-days`
 * whose resulting cutoff is a SAFE integer epoch (so `1e100` is a clean usage error, not a Postgres
 * internal error), a `--batch` in `1..MAX_AUDIT_PRUNE_BATCH`, and an exact-bare-`--yes` confirmation.
 */
function planPrune(v: StrictValues): PrunePlan | { error: string } {
  const daysRaw = v['older-than-days'];
  const days = Number(daysRaw);
  if (typeof daysRaw !== 'string' || !Number.isSafeInteger(days) || days < 1) {
    return { error: '--older-than-days <N> is required (a positive integer number of days; nothing is pruned without it)' };
  }
  const cutoff = Date.now() - days * 86_400_000;
  // The cutoff must be a safe integer AND within the ECMAScript Date range (±8.64e15 ms), else
  // rendering it (dry-run output) would throw "Invalid time value" AFTER doing DB work.
  if (!Number.isSafeInteger(cutoff) || cutoff < -8_640_000_000_000_000) {
    return { error: '--older-than-days is too large to represent a cutoff' };
  }
  const batch = typeof v.batch === 'string' ? Number(v.batch) : MAX_AUDIT_PRUNE_BATCH;
  if (!Number.isSafeInteger(batch) || batch < 1 || batch > MAX_AUDIT_PRUNE_BATCH) {
    return { error: `--batch must be an integer between 1 and ${MAX_AUDIT_PRUNE_BATCH}` };
  }
  const intent = destructiveIntent(v);
  if (typeof intent === 'object') return intent;
  return { cutoff, batch, dryRun: intent === 'dry-run' };
}

/** Execute a validated {@link PrunePlan}. Retention is an explicit operator choice — nothing prunes
 *  automatically, and keeping rows forever is the deliberate default. */
async function runPrune(db: Db, plan: PrunePlan): Promise<number> {
  const audit = new Audit(db);
  if (plan.dryRun) {
    // The count is ONLY for the preview — never on the destructive path, where an exact count of a
    // huge expired set could scan the table / hit statement_timeout before the first bounded delete.
    const n = await audit.countOlderThan(plan.cutoff);
    console.log(`DRY-RUN: ${n} audit row(s) before ${ts(plan.cutoff)}. Re-run with --yes to delete in bounded batches.`);
    return 0;
  }
  const deleted = await audit.pruneOlderThan(plan.cutoff, plan.batch);
  console.log(`Pruned ${deleted} audit row(s) before ${ts(plan.cutoff)}, in bounded batches.`);
  return 0;
}

function usage(): void {
  console.log(`vouchr: operator CLI (reads are metadata-only; \`migrate\`, \`revoke\`, \`rekey\`, \`prune\` mutate)

Usage: vouchr <command> [options]

Commands:
  migrate     Create the PostgreSQL schema (version 1); any other recorded
              version is refused, recreate the database. Run ONCE per deploy
              with a role that can create tables; the runtime then connects
              with a DML-only role. Idempotent and safe to run concurrently. Prefer VOUCHR_DATABASE_URL over --db (keeps the
              credential URL out of shell history / process args).
  inventory   List stored connections (metadata only; never tokens).
                --team <id>      filter by team
                --provider <id>  filter by provider
  channels    List per-channel config: team, channel, provider, identity, enabled.
                --team <id>      filter by team
  revoke      Break-glass bulk revocation for an incident (delete locally, then
              best-effort upstream revoke; audited, no secrets printed).
                --provider <id>  REQUIRED for a surgical revoke (refuses without it)
                --team <id>      narrow to one team
                --user <id>      narrow to one user's own credentials
                --channel <id>   narrow to one channel's shared credentials
                                  (--user and --channel are mutually exclusive)
                --yes            actually revoke (default is a dry-run)
                exits non-zero if any LOCAL deletion failed
              Deployment-wide (database/decryption compromise, #239):
                --all            revoke EVERY stored credential + authorization path
                                  (no owner scope; enumerates unregistered providers;
                                   invalidates Slack installations; local delete needs
                                   no key/KMS/provider config)
                --confirm ALL-CREDENTIALS  required to execute (dry-run otherwise)
                exits non-zero if any local credential/authorization row remains.
                Local deletion is NOT upstream revocation — rotate keys/secrets and
                have users reconnect; see SECURITY.md. Enable containment first
                (VOUCHR_LOCKDOWN) so no replica serves/mints during the wipe.
  doctor      Diagnostics (PASS/FAIL): master key(s), DB reachability, row counts.
                exits non-zero if any check fails
  rekey       Re-encrypt every stored ciphertext under the PRIMARY master key
              (the first VOUCHR_MASTER_KEYS entry). Old rows are decrypted with
              whichever configured key matches; envelope (KMS) rows are skipped.
              Idempotent and safe to interrupt/re-run; prints counts, never secrets.
                --dry-run        classify + count per key id/scheme; write nothing
                exits non-zero if any blob decrypts under NO configured key
  prune       Audit retention (#208): delete audit rows older than a cutoff, in
              bounded batches (never blocks normal inserts for long). Dry-run by
              default; retention is an explicit choice (no automatic pruning).
                --older-than-days <N>  REQUIRED (positive; nothing pruned without it)
                --batch <N>            rows per delete (default 10000)
                --yes                  actually delete (default is a dry-run count)
  help        This message.
  --version   Print the installed package version.

Store selection (shared with the app):
  --db <url>             PostgreSQL connection string (overrides VOUCHR_DATABASE_URL)
  VOUCHR_DATABASE_URL    PostgreSQL connection string (required; no embedded mode)
  VOUCHR_MASTER_KEY      base64 32-byte key (validated by doctor; loaded by revoke
                         for best-effort upstream token revocation, and by rekey)
  VOUCHR_MASTER_KEYS     comma-separated id:base64key entries; FIRST is the primary
                         (encrypts new writes), the rest decrypt-only (rotation)`);
}

/** Open the store for one command and always close it, even when the command throws. */
async function withDb<T>(databaseUrl: string | undefined, run: (db: Db) => Promise<T>): Promise<T> {
  const db = await openDb({ databaseUrl });
  try {
    return await run(db);
  } finally {
    await db.close();
  }
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  // Non-destructive commands parse strictly here, BEFORE any DB opens; the destructive ones parse
  // with strictParse inside their case. SEC-1: parseArgs' message quotes the offending flag, which
  // is raw argv and could be credential-shaped, so the error is fixed text and never echoes it.
  let f: Flags = {};
  const spec = cmd === undefined ? undefined : READ_SPECS[cmd];
  if (spec) {
    try {
      f = parseArgs({ args: rest, options: spec, strict: true, allowPositionals: false }).values as Flags;
    } catch {
      console.error(`${cmd}: invalid usage; run \`vouchr help\` (allowed: ${Object.keys(spec).map((k) => `--${k}`).join(', ')})`);
      return 2;
    }
  }

  switch (cmd) {
    case 'migrate': {
      // The ONLY command that creates/alters tables. Run it once per deploy/upgrade with a
      // schema-owner role; the runtime then connects with a DML-only role. Idempotent and safe to
      // run concurrently (advisory-locked). Prefer VOUCHR_DATABASE_URL over --db so a credential URL
      // stays out of shell history / process args.
      const { version } = await migrate({ databaseUrl: f.db });
      console.log(`OK schema migrated to version ${version}`);
      return 0;
    }
    case 'inventory':
    case 'channels': {
      await withDb(f.db, (db) => cmd === 'inventory' ? cmdInventory(db, f) : cmdChannels(db, f));
      return 0;
    }
    case 'revoke': {
      // Parse AND validate BEFORE opening the DB: a typo'd/empty scope or a valued --yes must be
      // rejected (exit 2) even when Postgres is unavailable — never widened to "delete everything".
      const p = strictParse(rest, REVOKE_SPEC);
      if ('error' in p) { console.error(`revoke: ${p.error}`); return 2; }
      const plan = planRevoke(p.values);
      if ('error' in plan) { console.error(`revoke: ${plan.error}`); return 2; }
      return withDb(plan.db, (db) => plan.mode === 'all' ? cmdRevokeAll(db, plan.execute) : cmdRevoke(db, plan));
    }
    case 'rekey': {
      return withDb(f.db, (db) => cmdRekey(db, f));
    }
    case 'prune': {
      const p = strictParse(rest, PRUNE_SPEC);
      if ('error' in p) { console.error(`prune: ${p.error}`); return 2; }
      const pre = planPrune(p.values); // days/batch/confirmation validated BEFORE the DB opens
      if ('error' in pre) { console.error(`prune: ${pre.error}`); return 2; }
      return withDb(p.values.db as string | undefined, (db) => runPrune(db, pre));
    }
    case 'doctor':
      return cmdDoctor(f);
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      usage();
      return 0;
    case '--version':
    case '-v':
      // Package self-reference: resolves from the repo (tsx) and from an installed copy (dist).
      console.log(require('@vouchr/core/package.json').version);
      return 0;
    default:
      // `cmd` is raw argv and may be a credential pasted in the wrong position (SEC-1).
      console.error('Unknown command.\n');
      usage();
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch(() => {
    // Database drivers and extension points can put connection strings, provider payloads, or
    // credential material in thrown values. The command-specific paths above already print safe
    // usage diagnostics; an unexpected top-level failure must stay deliberately opaque (SEC-1).
    console.error('vouchr: command failed. Run `vouchr doctor` to diagnose.');
    process.exit(1);
  });
