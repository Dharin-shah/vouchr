import type { Db } from '../core/db';
import {
  boundedEnvelopeProvider,
  seal,
  open,
  openEnvelope,
  toBuffer,
  type EnvelopeProvider,
  type MasterKeys,
} from '../core/crypto';
import type { Installation, InstallationQuery, InstallationStore, Logger } from '@slack/bolt';

export interface DbInstallationStoreOptions {
  /** Temporary cutover only: permit legacy direct/keyed rows while they are explicitly rewritten. */
  allowDirectRowsDuringMigration?: boolean;
}

/**
 * DB-backed Slack Bolt `InstallationStore` so ONE Vouchr deployment serves MANY
 * workspaces, and org-wide / Enterprise Grid installs. Without it Vouchr only knows
 * the single env bot token and just one workspace works.
 *
 * The full Installation carries the bot (and user) tokens, which are secrets, so the JSON is
 * encrypted at rest, exactly like the Vault. Both columns go through `seal`/`open` (#241): with an
 * `EnvelopeProvider` configured they are per-secret DEK + external-KEK envelope ciphertext (scheme
 * 0x01), the same at-rest scheme Vault credentials use — so a database + direct-master compromise
 * cannot read installation bot tokens when the operator relies on KMS. Without a provider the direct
 * (scheme-0 / keyed) path is byte-for-byte unchanged. With a provider, reads require envelope
 * ciphertext by default: direct rows are accepted only through the explicit temporary
 * `allowDirectRowsDuringMigration` option and convert on their next write (re-install/re-auth). A KMS
 * unwrap failure fails closed with a fixed error, never a silent direct fallback. Pass the SAME
 * envelope instance the deployment wires into `createVouchr({ envelope })`. Rows are keyed by
 * (enterprise_id, team_id) using the same shape Bolt's own stores use.
 */
export class DbInstallationStore implements InstallationStore {
  private envelope?: EnvelopeProvider;
  private allowDirectRowsDuringMigration: boolean;

  constructor(
    private db: Db,
    private key: MasterKeys,
    envelope?: EnvelopeProvider,
    options: DbInstallationStoreOptions = {},
  ) {
    if (typeof options !== 'object' || options === null || Array.isArray(options)
      || Object.getPrototypeOf(options) !== Object.prototype) {
      throw new Error('DbInstallationStore: options must be a plain object');
    }
    if (options.allowDirectRowsDuringMigration !== undefined
      && typeof options.allowDirectRowsDuringMigration !== 'boolean') {
      throw new Error('DbInstallationStore: allowDirectRowsDuringMigration must be boolean');
    }
    // Bolt resolves an installation before listener acknowledgement. Bound both the KMS wait and
    // genuinely-unsettled work so an outage cannot pin every Slack request or grow promises forever.
    this.envelope = envelope === undefined ? undefined : boundedEnvelopeProvider(envelope);
    this.allowDirectRowsDuringMigration = options.allowDirectRowsDuringMigration ?? false;
  }

  /**
   * Deterministic row key. Mirrors Bolt's keying: an enterprise (org-wide) install is
   * keyed by enterprise id alone (no team segment); every other install by
   * enterprise+team. An explicit key column sidesteps the SQLite/Postgres difference in
   * how NULLs behave inside a UNIQUE constraint.
   */
  private static rowKey(
    enterpriseId: string | undefined,
    teamId: string | undefined,
    isEnterpriseInstall: boolean,
  ): string {
    const ent = enterpriseId ?? '';
    const team = isEnterpriseInstall ? '' : (teamId ?? '');
    return `${ent}:${team}`;
  }

  async storeInstallation<A extends 'v1' | 'v2'>(installation: Installation<A, boolean>, _logger?: Logger): Promise<void> {
    const isOrg = installation.isEnterpriseInstall === true;
    const enterpriseId = installation.enterprise?.id;
    const teamId = installation.team?.id;
    // bot_token is denormalized per Bolt's InstallationStore shape; resolution still goes through
    // fetchInstallation. Kept for ops lookups without decrypting the whole blob. Both columns are
    // encrypted at rest.
    const botToken = installation.bot?.token ?? null;
    // Seal both columns BEFORE the write: a KMS wrap failure (envelope path) throws here, so the
    // INSERT never runs and no partial installation row is committed.
    const botTokenEnc = botToken ? await seal(botToken, this.key, this.envelope) : null;
    const dataEnc = await seal(JSON.stringify(installation), this.key, this.envelope);
    await this.db.run(
      `INSERT INTO installation (id, enterprise_id, team_id, bot_token, data, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         enterprise_id=excluded.enterprise_id, team_id=excluded.team_id,
         bot_token=excluded.bot_token, data=excluded.data, updated_at=excluded.updated_at`,
      [
        DbInstallationStore.rowKey(enterpriseId, teamId, isOrg),
        enterpriseId ?? null,
        isOrg ? null : (teamId ?? null),
        botTokenEnc,
        dataEnc,
        Date.now(),
      ],
    );
  }

  async fetchInstallation(query: InstallationQuery<boolean>, _logger?: Logger): Promise<Installation<'v1' | 'v2', boolean>> {
    if (query.isEnterpriseInstall && query.enterpriseId === undefined) {
      throw new Error('enterpriseId is required to fetch an enterprise installation');
    }
    // Exact key first; then fall back to the org-wide install: an Enterprise Grid org-wide
    // install serves every workspace in the org, so a team-level query must resolve to it.
    const keys = [DbInstallationStore.rowKey(query.enterpriseId, query.teamId, query.isEnterpriseInstall)];
    if (!query.isEnterpriseInstall && query.enterpriseId !== undefined) {
      keys.push(DbInstallationStore.rowKey(query.enterpriseId, undefined, true));
    }
    for (const id of keys) {
      const row = (await this.db.get(`SELECT data FROM installation WHERE id=?`, [id])) as { data: unknown } | undefined;
      // Production reads use the envelope-only path. The format-dispatching `open` path exists only
      // inside the explicit temporary migration window; either path surfaces fixed KMS failures.
      if (row) {
        const ciphertext = toBuffer(row.data);
        const plaintext = this.envelope && !this.allowDirectRowsDuringMigration
          ? await openEnvelope(ciphertext, this.envelope)
          : await open(ciphertext, this.key, this.envelope);
        try {
          const parsed: unknown = JSON.parse(plaintext);
          if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error();
          return parsed as Installation;
        } catch {
          // JSON.parse includes fragments of its input in Node's error text. Never preserve it as a
          // cause: authenticated-but-misplaced ciphertext (for example bot_token copied into data)
          // would otherwise turn a Slack token into an AuthorizationError/log message (SEC-1).
          throw new Error('vouchr: stored Slack installation data is invalid');
        }
      }
    }
    throw new Error(`No installation found (enterprise_id: ${query.enterpriseId}, team_id: ${query.teamId})`);
  }

  async deleteInstallation(query: InstallationQuery<boolean>, _logger?: Logger): Promise<void> {
    await this.db.run(
      `DELETE FROM installation WHERE id=?`,
      [DbInstallationStore.rowKey(query.enterpriseId, query.teamId, query.isEnterpriseInstall)],
    );
  }
}
