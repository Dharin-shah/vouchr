#!/usr/bin/env node
/**
 * broker-seed: provision a credential into the vault WITHOUT Slack — the consent path for the
 * headless broker's shared/referenced credentials.
 *
 *   broker-seed reference --provider confluence --team T1 --user U1 \
 *       --source aws-sm --secret-ref arn:aws:secretsmanager:...:secret/xyz [--scopes read,write]
 *   broker-seed key --provider internal --team T1 --channel C1 [--scopes a,b]  (token in env)
 *
 * For `key` mode, prefer the VOUCHR_SEED_ACCESS_TOKEN env var — a `--access-token` FLAG lands in
 * process argv, visible via `ps`/`/proc` to co-tenants. The flag is kept only for interactive use.
 *
 * `reference` stores a POINTER to an external secret manager (nothing sensitive at rest here).
 * `key` stores a static token, encrypted at rest by VOUCHR_MASTER_KEY (+ envelope if configured).
 *
 * PER-USER credentials are NOT this tool's job: run the Bolt control-plane Vouchr against the SAME
 * Postgres DB and let users connect via Slack; the broker then reads what they consented to. This
 * CLI covers only operator-provisioned shared/referenced creds. Reads DB + key from env (see
 * DEPLOYMENT.md): VOUCHR_DATABASE_URL / VOUCHR_DB, VOUCHR_MASTER_KEY.
 */
import { openDb } from '../src/core/db';
import { loadMasterKey } from '../src/core/crypto';
import { Vault } from '../src/core/vault';
import { userOwner, channelOwner } from '../src/core/owner';
import type { EnvelopeProvider } from '../src/core/crypto';
import { isPostgresUrl } from '../src/core/options';

function parseFlags(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const eq = a.indexOf('=');
    if (eq !== -1) out[a.slice(2, eq)] = a.slice(eq + 1);
    else out[a.slice(2)] = argv[++i] ?? '';
  }
  return out;
}

function die(msg: string): never {
  console.error(`broker-seed: ${msg}`);
  process.exit(1);
}

const USAGE = `vouchr-seed — provision an operator/shared credential into the vault (no Slack)

Usage: vouchr-seed reference --provider <id> --team <T> (--user <U>|--channel <C>) \\
                   --source <secret-manager-id> --secret-ref <ref> [--scopes a,b]
       vouchr-seed key --provider <id> --team <T> (--user <U>|--channel <C>) [--scopes a,b]
                   (token from VOUCHR_SEED_ACCESS_TOKEN env; --access-token is visible in ps)
       vouchr-seed --help

Reads DB + key from env: VOUCHR_DATABASE_URL|VOUCHR_DB, VOUCHR_MASTER_KEY. See DEPLOYMENT.md.`;

async function main(): Promise<void> {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === '--help' || mode === '-h' || mode === 'help') {
    console.log(USAGE);
    return;
  }
  if (mode !== 'reference' && mode !== 'key') {
    die('usage: broker-seed <reference|key> --provider <id> --team <T> (--user <U>|--channel <C>) ...');
  }
  const f = parseFlags(rest);
  if (!f.provider) die('--provider is required');
  if (!f.team) die('--team is required');
  if (!f.user && !f.channel) die('one of --user or --channel is required');
  if (f.user && f.channel) die('set --user OR --channel, not both');

  const owner = f.user
    ? userOwner({ enterpriseId: f.enterprise ?? null, teamId: f.team, userId: f.user })
    : channelOwner(f.team, f.channel, f.enterprise ?? null);
  // scopes stored space-separated, matching the OAuth path.
  const scopes = f.scopes ? f.scopes.split(',').map((s) => s.trim()).filter(Boolean).join(' ') : undefined;

  const url = process.env.VOUCHR_DATABASE_URL ?? process.env.DATABASE_URL;
  const backend = isPostgresUrl(url) ? 'postgres' : 'sqlite';
  let envelope: EnvelopeProvider | undefined;
  if (process.env.VOUCHR_KMS_KEY_ID) {
    const { kmsEnvelope, awsKmsClient } = await import('../src/adapters/kms');
    envelope = kmsEnvelope(process.env.VOUCHR_KMS_KEY_ID, await awsKmsClient({ region: process.env.AWS_REGION }));
  }

  const db = await openDb(backend === 'postgres' ? { databaseUrl: url } : { dbPath: process.env.VOUCHR_DB });
  const vault = new Vault(db, loadMasterKey(), {}, envelope);
  try {
    if (mode === 'reference') {
      if (!f.source) die('--source is required for reference mode (the secret manager id)');
      if (!f['secret-ref']) die('--secret-ref is required for reference mode');
      await vault.reference(owner, f.provider, { source: f.source, secretRef: f['secret-ref'], scopes });
    } else {
      // Prefer the env var (not visible in `ps`); fall back to the argv flag for interactive use.
      const accessToken = process.env.VOUCHR_SEED_ACCESS_TOKEN || f['access-token'];
      if (!accessToken) die('key mode needs a token: set VOUCHR_SEED_ACCESS_TOKEN (preferred) or --access-token');
      await vault.upsert(owner, f.provider, {
        accessToken,
        refreshToken: f['refresh-token'] ?? null,
        scopes: scopes ?? '',
        expiresAt: null,
        externalAccount: null,
      });
    }
    console.log(`[vouchr] seeded ${mode} credential provider=${f.provider} owner=${f.user ? 'user' : 'channel'}`);
  } finally {
    await db.close();
  }
}

if (require.main === module) {
  main().catch((e) => die((e as Error).message));
}
