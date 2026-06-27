export interface PolicyRule {
  /** When true, allow everywhere except denyChannels. When false, allow only in allowChannels. */
  defaultAllow: boolean;
  allowChannels?: string[];
  denyChannels?: string[];
}

/**
 * Minimal provider × channel allow/deny.
 * No rule for a provider = allowed (default), or denied when opts.defaultDeny is set
 * (enterprise opt-in mode: a provider must be explicitly given a rule to be usable).
 * defaultDeny only changes the no-rule fallback; per-rule semantics are identical in both modes.
 */
export class Policy {
  constructor(
    private rules: Record<string, PolicyRule> = {},
    private opts: { defaultDeny?: boolean } = {},
  ) {}

  check(provider: string, channel: string | null): boolean {
    const r = this.rules[provider];
    if (!r) return !this.opts.defaultDeny;
    if (channel && r.denyChannels?.includes(channel)) return false;
    if (r.defaultAllow) return true;
    return !!(channel && r.allowChannels?.includes(channel));
  }
}
