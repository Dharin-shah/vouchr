import { randomBytes } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Provider } from './providers';
import { sha256base64url } from './crypto';
import { DRY_RUN_CODE } from './dryRun';

const STATE_TTL_MS = 10 * 60 * 1000;

export interface ConsentRow {
  state: string;
  identity: SlackIdentity;
  provider: string;
  channel: string | null;
  pkceVerifier: string;
}

/** Manages the single-use OAuth `state` + PKCE for a consent round-trip. */
export class Consent {
  /** `dryRun` (#116): begin() then returns a LOCAL authorize URL — the redirect target itself with
   *  a synthetic code — instead of the provider's, so clicking Connect completes instantly and
   *  offline. The state row, single-use consume, and TTL stay exactly the real machinery. */
  constructor(
    private db: Db,
    private dryRun = false,
  ) {}

  /** Create a single-use consent request and return the provider authorize URL. */
  async begin(
    i: SlackIdentity,
    provider: Provider,
    redirectUri: string,
    channel: string | null,
  ): Promise<{ authorizeUrl: string; state: string }> {
    const state = randomBytes(32).toString('base64url');
    const pkceVerifier = randomBytes(48).toString('base64url');

    await this.db.run(
      `INSERT INTO consent_request
         (state, enterprise_id, team_id, user_id, provider, channel, pkce_verifier, created_at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [state, i.enterpriseId, i.teamId, i.userId, provider.id, channel, pkceVerifier, Date.now()],
    );

    // #116 dry-run: the authorize URL is the ONLY thing replaced — an instantly-succeeding local
    // redirect into the real callback. The code is synthetic; the single-use `state` above is what
    // the callback verifies, exactly as in production.
    if (this.dryRun) {
      const u = new URL(redirectUri);
      u.searchParams.set('code', DRY_RUN_CODE);
      u.searchParams.set('state', state);
      return { authorizeUrl: u.toString(), state };
    }

    const url = new URL(provider.authorizeUrl);
    url.searchParams.set('client_id', provider.clientId!); // guaranteed for oauth providers (defineProvider)
    url.searchParams.set('redirect_uri', redirectUri);
    if (provider.scopesDefault.length) {
      url.searchParams.set('scope', provider.scopesDefault.join(' '));
    }
    url.searchParams.set('state', state);
    url.searchParams.set('response_type', 'code');
    if (provider.pkce) {
      url.searchParams.set('code_challenge', sha256base64url(pkceVerifier));
      url.searchParams.set('code_challenge_method', 'S256');
    }
    for (const [k, v] of Object.entries(provider.authorizeParams ?? {})) {
      url.searchParams.set(k, v);
    }
    return { authorizeUrl: url.toString(), state };
  }

  /** Delete any in-flight consent for a user, preventing a pending OAuth from
   *  resurrecting a connection for a just-offboarded user. */
  async deleteForUser(i: SlackIdentity): Promise<void> {
    await this.db.run(`DELETE FROM consent_request WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
  }

  /**
   * Durable fail-closed offboarding gate (GHSA-25m2): record that this user was offboarded NOW.
   * `consume()` refuses any consent state minted at or before this instant, so even if the row
   * purge in {@link deleteForUser} transiently fails, a pending pre-offboarding "Connect" can
   * never complete and resurrect a credential. Tombstones are permanent and tiny (one row per
   * offboarded user); a legitimately re-onboarded user starts a NEW consent, which is newer than
   * the tombstone and passes. Re-offboarding refreshes the timestamp.
   */
  async markOffboarded(i: SlackIdentity): Promise<void> {
    await this.db.run(
      `INSERT INTO offboard_tombstone (team_id, user_id, created_at) VALUES (?,?,?)
       ON CONFLICT(team_id, user_id) DO UPDATE SET created_at=excluded.created_at`,
      [i.teamId, i.userId, Date.now()],
    );
  }

  /** Delete in-flight consent for ONE provider (break-glass bulk revocation), so a pending "Connect"
   *  click can't resurrect the credential we just revoked. */
  async deleteForUserProvider(teamId: string, userId: string, provider: string): Promise<void> {
    await this.db.run(`DELETE FROM consent_request WHERE team_id=? AND user_id=? AND provider=?`, [teamId, userId, provider]);
  }

  /** Delete consent requests older than the state TTL (abandoned "Connect" clicks). */
  async sweepStale(): Promise<number> {
    const cutoff = Date.now() - STATE_TTL_MS;
    return (await this.db.run(`DELETE FROM consent_request WHERE created_at < ?`, [cutoff])).changes;
  }

  /** Newest pending state for (user, provider) — the dry-run completeConsent lookup (#116). Scoped
   *  to a team when one is given. Read-only: consume() stays the single-use gate. */
  async latestStateFor(userId: string, provider: string, teamId?: string): Promise<string | null> {
    const row = (await this.db.get(
      `SELECT state FROM consent_request WHERE user_id=? AND provider=?${teamId ? ' AND team_id=?' : ''}
       ORDER BY created_at DESC LIMIT 1`,
      teamId ? [userId, provider, teamId] : [userId, provider],
    )) as any;
    return row?.state ?? null;
  }

  /** Look up and consume (single-use) a consent request. Returns null if absent/expired — or if
   *  the user was offboarded at/after the state was minted (the tombstone gate, GHSA-25m2). */
  async consume(state: string): Promise<ConsentRow | null> {
    // Atomic single-use: DELETE ... RETURNING so two concurrent callbacks can't both pass the
    // check (a get-then-delete has a TOCTOU window on multi-instance Postgres). Both engines support it.
    const row = (await this.db.get(`DELETE FROM consent_request WHERE state=? RETURNING *`, [state])) as any;
    if (!row) return null;
    if (Date.now() - row.created_at > STATE_TTL_MS) return null;
    // Offboarding tombstone (GHSA-25m2): a consent minted at or before the user's offboarding can
    // never complete, even when the offboarding row-purge transiently failed. Checked AFTER the
    // single-use delete, so the state is spent either way.
    const tomb = (await this.db.get(
      `SELECT created_at FROM offboard_tombstone WHERE team_id=? AND user_id=?`,
      [row.team_id, row.user_id],
    )) as any;
    if (tomb && tomb.created_at >= row.created_at) return null;
    return {
      state: row.state,
      identity: {
        enterpriseId: row.enterprise_id,
        teamId: row.team_id,
        userId: row.user_id,
      },
      provider: row.provider,
      channel: row.channel,
      pkceVerifier: row.pkce_verifier,
    };
  }
}
