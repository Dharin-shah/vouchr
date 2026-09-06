import type { ChannelIdentity } from './channelConfig';
import type { Db } from './db';
import type { SlackIdentity } from './identity';
import {
  isInteractionId,
  newInteractionId,
  POSTGRES_NOW_US_SQL,
  WORKER_SESSION_IDLE_TTL_US,
  WORKER_SESSION_MAX_TTL_US,
} from './interaction';
import { userOwner, type Owner } from './owner';

/**
 * A worker's session in one conversation for one provider (#360). Whoever the agent acts as is the
 * one who authorizes: a worker has no human requester, so a channel member authorizes its request as
 * themselves, and the conversation (the thread the token names, else the channel) becomes that
 * member's session for that worker and provider.
 *
 * Unbound (`memberUserId` null): the row's `id` stands in as the credential generation on the
 * worker's pending approval rows, so the same action deduplicates to one prompt and any member may
 * authorize. Bound: the member who clicked, the exact credential generation they held, and when. The
 * decision rewrites the pending row to that member's credential; every later request of the worker
 * in the same conversation asks that member privately and runs as them once they confirm.
 *
 * Fences: `expiresAt` is the idle lifetime, extended only by the bound member's own activity (a
 * decision, a spend of a grant they made) and never past `boundAt` + the absolute cap; the worker's
 * own requests do not extend it. A disconnect or reconnect changes the member's live credential id;
 * offboarding tombstones the member after `boundAt`. Any of them ends the session, and the next
 * request goes back to any member.
 */
export interface WorkerSession {
  id: string;
  memberUserId: string | null;
  credentialId: string | null;
  boundAt: number | null;
}

/** The conversation one session is scoped to. `thread` null means the channel itself. */
export interface WorkerSessionScope {
  teamId: string;
  channel: string;
  thread: string | null;
  workerUserId: string;
  provider: string;
}

function toSession(r: any): WorkerSession {
  return {
    id: r.id,
    memberUserId: r.member_user_id ?? null,
    credentialId: r.credential_id ?? null,
    boundAt: r.bound_at ?? null,
  };
}

const SCOPE_SQL = 'team_id=? AND channel=? AND thread=? AND worker_user_id=? AND provider=?';
const scopeParams = (s: WorkerSessionScope): unknown[] => [s.teamId, s.channel, s.thread ?? '', s.workerUserId, s.provider];

/** The live session for one scope, or null when none exists or it idled out. */
export async function workerSessionFor(db: Db, scope: WorkerSessionScope): Promise<WorkerSession | null> {
  const row = await db.get<any>(
    `SELECT id, member_user_id, credential_id, bound_at FROM worker_session
     WHERE ${SCOPE_SQL} AND expires_at>${POSTGRES_NOW_US_SQL}`,
    scopeParams(scope),
  );
  return row ? toSession(row) : null;
}

/**
 * The session a worker's request runs under: the live bound session when the bound member still
 * holds exactly the credential generation it was bound to, else a fresh unbound session (a dead,
 * expired, or absent one is replaced in place). Reading it does not extend it: only the member's
 * decisions and spends do (touchWorkerSession). `liveCredential` reads the member's current
 * generation without decrypting anything.
 */
export async function beginWorkerSession(
  db: Db,
  scope: WorkerSessionScope,
  liveCredential: (member: SlackIdentity, provider: string) => Promise<string | null>,
): Promise<WorkerSession> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const current = await workerSessionFor(db, scope);
    if (current) {
      const member: SlackIdentity | null = current.memberUserId
        ? { enterpriseId: null, teamId: scope.teamId, userId: current.memberUserId }
        : null;
      if (!member || (await liveCredential(member, scope.provider)) === current.credentialId) return current;
    }
    // Absent, idled out, or bound to a credential generation that no longer exists: start over with
    // a fresh unbound generation. The conditional conflict update only replaces the exact row read
    // above (or an expired one), so a concurrent bind or replacement by another replica wins and is
    // re-read on the next attempt.
    const row = await db.get<any>(
      `INSERT INTO worker_session (id, team_id, channel, thread, worker_user_id, provider, member_user_id, credential_id, bound_at, expires_at)
       VALUES (?,?,?,?,?,?,NULL,NULL,NULL,${POSTGRES_NOW_US_SQL}+?)
       ON CONFLICT (team_id, channel, thread, worker_user_id, provider) DO UPDATE SET
         id=excluded.id, member_user_id=NULL, credential_id=NULL, bound_at=NULL, expires_at=excluded.expires_at
       WHERE worker_session.expires_at<=${POSTGRES_NOW_US_SQL} OR worker_session.id IS NOT DISTINCT FROM ?
       RETURNING id, member_user_id, credential_id, bound_at`,
      [newInteractionId(), ...scopeParams(scope), WORKER_SESSION_IDLE_TTL_US, current?.id ?? null],
    );
    if (row) return toSession(row);
  }
  throw new Error('worker session could not be recorded; retry');
}

/** The unbound session whose id is this placeholder generation, if it is still live. */
export async function unboundWorkerSessionLive(db: Db, id: string): Promise<boolean> {
  if (!isInteractionId(id)) return false;
  return !!(await db.get(
    `SELECT 1 FROM worker_session WHERE id=? AND member_user_id IS NULL AND expires_at>${POSTGRES_NOW_US_SQL}`,
    [id],
  ));
}

/** Bind an unbound session to the member who authorized and the exact credential generation they
 * hold. False when the session was already bound, replaced, or expired (the caller treats the
 * decision as stale). */
export async function bindWorkerSession(db: Db, id: string, memberUserId: string, credentialId: string): Promise<boolean> {
  if (!isInteractionId(id) || !isInteractionId(credentialId)) return false;
  return (await db.run(
    `UPDATE worker_session SET member_user_id=?, credential_id=?, bound_at=${POSTGRES_NOW_US_SQL},
       expires_at=${POSTGRES_NOW_US_SQL}+?
     WHERE id=? AND member_user_id IS NULL AND expires_at>${POSTGRES_NOW_US_SQL}`,
    [memberUserId, credentialId, WORKER_SESSION_IDLE_TTL_US, id],
  )).changes === 1;
}

/** The bound member's activity (their decision, their grant spent) extends the idle lifetime, never
 * past the absolute cap from the binding click. Called only after a member decision, never for the
 * worker's own request. */
export async function touchWorkerSession(db: Db, id: string): Promise<void> {
  if (!isInteractionId(id)) return;
  await db.run(
    `UPDATE worker_session SET expires_at=LEAST(${POSTGRES_NOW_US_SQL}+?, COALESCE(bound_at,${POSTGRES_NOW_US_SQL})+?)
     WHERE id=? AND expires_at>${POSTGRES_NOW_US_SQL}`,
    [WORKER_SESSION_IDLE_TTL_US, WORKER_SESSION_MAX_TTL_US, id],
  );
}

/** The outcome of a worker's owner resolution: whose credential its request runs under, or why no
 * member can authorize it. Transport-agnostic; the broker maps codes to HTTP statuses. */
export type WorkerResolution =
  | { status: 'resolved'; owner: Owner; credentialId: string }
  | { status: 'refused'; code: 'no_channel' | 'ineligible' | 'shared_identity' };

/**
 * The ONE decision for a worker's request (#360): the worker has no credential of its own and none
 * is looked up. Refused fail-closed where no member can authorize: a personal conversation (no
 * governed channel), a channel the eligibility verdict does not clear, or a channel whose identity
 * for the provider is the shared credential. Otherwise the request runs under the worker's session
 * in the conversation: the bound member's credential generation when a member has bound it, else
 * the unbound session's id as the placeholder generation (the exact action deduplicates to one
 * prompt any member may answer, and the click decides the owner).
 */
export async function resolveWorkerOwner(
  db: Db,
  i: {
    acting: SlackIdentity;
    provider: string;
    governableChannel: string | null;
    thread: string | null;
    eligible: boolean;
    identity: ChannelIdentity;
    liveCredential: (member: SlackIdentity, provider: string) => Promise<string | null>;
  },
): Promise<WorkerResolution> {
  if (!i.governableChannel) return { status: 'refused', code: 'no_channel' };
  if (!i.eligible) return { status: 'refused', code: 'ineligible' };
  if (i.identity !== 'person') return { status: 'refused', code: 'shared_identity' };
  const session = await beginWorkerSession(
    db,
    { teamId: i.acting.teamId, channel: i.governableChannel, thread: i.thread, workerUserId: i.acting.userId, provider: i.provider },
    i.liveCredential,
  );
  if (session.memberUserId && session.credentialId) {
    const member: SlackIdentity = { enterpriseId: i.acting.enterpriseId ?? null, teamId: i.acting.teamId, userId: session.memberUserId };
    return { status: 'resolved', owner: userOwner(member), credentialId: session.credentialId };
  }
  return { status: 'resolved', owner: userOwner(i.acting), credentialId: session.id };
}

/** Offboarding a member ends every session bound to them; their pending grants are purged with
 * their credentials. Offboarding the worker ends every session it holds. */
export async function endWorkerSessionsForUser(db: Db, identity: SlackIdentity): Promise<void> {
  await db.run(
    `DELETE FROM worker_session WHERE team_id=? AND (member_user_id=? OR worker_user_id=?)`,
    [identity.teamId, identity.userId, identity.userId],
  );
}

/** Reclaim idled-out sessions. Runs on the lifecycle sweep timer. */
export async function sweepWorkerSessions(db: Db): Promise<number> {
  return (await db.run(`DELETE FROM worker_session WHERE expires_at<=${POSTGRES_NOW_US_SQL}`)).changes;
}
