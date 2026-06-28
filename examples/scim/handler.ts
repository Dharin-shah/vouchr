import { ProviderRegistry, github, google, offboardUserEverywhere } from '../../src';
import { openDb } from '../../src/core/db';
import { loadMasterKey } from '../../src/core/crypto';
import { Vault } from '../../src/core/vault';
import { Audit } from '../../src/core/audit';
import { Consent } from '../../src/core/consent';

// ─────────────────────────────────────────────────────────────────────────────
// SCIM / admin-API deprovisioning hook.
//
// Slack does NOT call your app for SCIM lifecycle events — your IdP (Okta, Entra,
// etc.) or your own admin tooling does. When a user is deactivated org-wide, that
// system POSTs here and we revoke every connection the user holds across EVERY
// workspace in the Enterprise Grid org — not just one team.
//
// Connect / consent stays in the Slack app (see the bolt-* examples). This endpoint
// is offboarding ONLY: it removes credentials, it never mints them.
// ─────────────────────────────────────────────────────────────────────────────

/** The minimal shape a deprovision webhook needs to give us. */
export interface DeprovisionEvent {
  /** Enterprise Grid org id. Optional: omit to span by the (org-wide-unique) Slack userId alone. */
  enterpriseId?: string | null;
  /** The Slack userId being deactivated. */
  userId: string;
}

/**
 * Build the deps once and reuse them. Same Postgres + same master key as the Slack
 * app — this MUST point at the very store the app writes connections to, or there is
 * nothing to offboard. Postgres so the webhook can run as its own stateless service.
 */
async function deps() {
  const db = await openDb({ databaseUrl: process.env.VOUCHR_DATABASE_URL });
  const key = loadMasterKey();
  return {
    db,
    vault: new Vault(db, key),
    audit: new Audit(db),
    consent: new Consent(db),
    // Pass the SAME providers the Slack app uses, so upstream token revocation fires
    // per connection. Omit the registry to do local-only deletes (no upstream revoke).
    registry: new ProviderRegistry([github(), google()]),
  };
}

/**
 * Offboard a deprovisioned user everywhere. Best-effort and non-fatal per workspace;
 * returns a per-team summary of what was removed. Never returns or logs secrets.
 */
export async function onDeprovision(
  event: DeprovisionEvent,
): Promise<{ teamId: string; providers: string[] }[]> {
  const { db, vault, audit, consent, registry } = await deps();
  try {
    const summary = await offboardUserEverywhere(
      db,
      vault,
      audit,
      consent,
      { enterpriseId: event.enterpriseId, userId: event.userId },
      registry,
      'scim-deprovision',
    );
    // Log counts only — provider ids and team ids are not secret; tokens never appear here.
    const removed = summary.reduce((n, t) => n + t.providers.length, 0);
    console.log(`[vouchr] deprovisioned ${event.userId}: ${removed} connection(s) across ${summary.length} team(s)`);
    return summary;
  } finally {
    await db.close();
  }
}

// ── Example wiring: a tiny Node http server. Swap for Express/Lambda/etc. ──
//
//   import { createServer } from 'node:http';
//   createServer(async (req, res) => {
//     if (req.method !== 'POST' || req.url !== '/scim/deprovision') { res.writeHead(404).end(); return; }
//     // AUTHENTICATE the caller here (shared secret / mTLS / IdP signature) BEFORE acting.
//     let body = ''; for await (const c of req) body += c;
//     const { enterpriseId, userId } = JSON.parse(body) as DeprovisionEvent;
//     if (!userId) { res.writeHead(400).end('userId required'); return; }
//     const summary = await onDeprovision({ enterpriseId, userId });
//     res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(summary));
//   }).listen(Number(process.env.PORT ?? 3001));
