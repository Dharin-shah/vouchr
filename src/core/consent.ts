import { randomBytes } from 'node:crypto';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import type { Provider } from './providers';
import { sha256base64url } from './crypto';

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
  constructor(private db: Db) {}

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

  /** Delete any in-flight consent for a user — prevents a pending OAuth from
   *  resurrecting a connection for a just-offboarded user. */
  async deleteForUser(i: SlackIdentity): Promise<void> {
    await this.db.run(`DELETE FROM consent_request WHERE team_id=? AND user_id=?`, [i.teamId, i.userId]);
  }

  /** Delete consent requests older than the state TTL (abandoned "Connect" clicks). */
  async sweepStale(): Promise<number> {
    const cutoff = Date.now() - STATE_TTL_MS;
    return (await this.db.run(`DELETE FROM consent_request WHERE created_at < ?`, [cutoff])).changes;
  }

  /** Look up and consume (single-use) a consent request. Returns null if absent/expired. */
  async consume(state: string): Promise<ConsentRow | null> {
    const row = (await this.db.get(`SELECT * FROM consent_request WHERE state=?`, [state])) as any;
    if (!row) return null;
    // Single-use: delete regardless of validity.
    await this.db.run(`DELETE FROM consent_request WHERE state=?`, [state]);
    if (Date.now() - row.created_at > STATE_TTL_MS) return null;
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
