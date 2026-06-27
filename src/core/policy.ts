export interface PolicyRule {
  /** When true, allow everywhere except denyChannels. When false, allow only in allowChannels. */
  defaultAllow: boolean;
  allowChannels?: string[];
  denyChannels?: string[];
}

/** Minimal provider × channel allow/deny. No rule for a provider = allowed. */
export class Policy {
  constructor(private rules: Record<string, PolicyRule> = {}) {}

  check(provider: string, channel: string | null): boolean {
    const r = this.rules[provider];
    if (!r) return true;
    if (channel && r.denyChannels?.includes(channel)) return false;
    if (r.defaultAllow) return true;
    return !!(channel && r.allowChannels?.includes(channel));
  }
}
