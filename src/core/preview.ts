import { randomUUID } from 'node:crypto';

/**
 * A private preview waiting for the recipient's Share/Dismiss decision. Holds the RENDERED text the
 * agent showed ephemerally (Slack cannot read an ephemeral message back), so a Share click can
 * repost exactly what the human reviewed. Provider DATA, never credentials — but still deliberately
 * ephemeral: previews live only in memory, never in the database (persisting provider responses at
 * rest would be a new data category for Vouchr). Losing them on restart is the correct failure:
 * the share button answers "preview expired, ask again".
 */
export interface PendingPreview {
  teamId: string;
  /** The only user allowed to share or dismiss this preview (the ephemeral recipient). */
  userId: string;
  /** The channel the preview was issued in; a share may only post back to the same place. */
  channel: string;
  thread: string | null;
  provider: string;
  title: string;
  lines: string[];
  createdAt: number;
}

/**
 * In-memory single-use store for pending private previews. The claim check is the security
 * decision (SEC-3: a button click's fields are forgeable; the CLAIM is authorized here, server-side,
 * against what was stored at issue time), so it lives in core and is unit-testable offline.
 *
 * ponytail: in-memory map — a multi-process Bolt deployment needs a shared store (the DB tables
 * deliberately don't hold provider data; use a cache tier) before share buttons work across workers.
 */
export class PendingPreviews {
  private map = new Map<string, PendingPreview>();

  constructor(
    private ttlMs = 10 * 60_000,
    private max = 500,
    private now: () => number = Date.now,
  ) {}

  /** Store a preview and return its unguessable id (the ONLY thing the button value carries). */
  put(p: Omit<PendingPreview, 'createdAt'>): string {
    this.sweep();
    // Cap memory: evict oldest first (Map preserves insertion order). An evicted preview simply
    // reports "expired" on click.
    while (this.map.size >= this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
    const id = randomUUID();
    this.map.set(id, { ...p, createdAt: this.now() });
    return id;
  }

  /**
   * Single-use claim for sharing. Returns the preview ONLY when `id` exists, is unexpired, and the
   * claim matches the stored recipient + team + channel — then removes it (a share, like an OAuth
   * `state`, happens at most once). A mismatched claim returns null WITHOUT consuming the entry, so
   * a forged click can't burn the rightful recipient's preview.
   */
  take(id: string, claim: { userId: string; teamId: string; channel: string }): PendingPreview | null {
    const p = this.peek(id);
    if (!p) return null;
    if (p.userId !== claim.userId || p.teamId !== claim.teamId || p.channel !== claim.channel) return null;
    this.map.delete(id);
    return p;
  }

  /** Drop a preview on Dismiss. Same claim rule as take(); returns whether anything was removed. */
  dismiss(id: string, claim: { userId: string; teamId: string; channel: string }): boolean {
    return this.take(id, claim) !== null;
  }

  private peek(id: string): PendingPreview | null {
    const p = this.map.get(id);
    if (!p) return null;
    if (this.now() - p.createdAt > this.ttlMs) {
      this.map.delete(id);
      return null;
    }
    return p;
  }

  private sweep(): void {
    for (const [id, p] of this.map) {
      if (this.now() - p.createdAt > this.ttlMs) this.map.delete(id);
    }
  }
}
