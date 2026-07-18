import type { SlackIdentity } from '../core/identity';

/** HTML-escape untrusted values before inlining: provider/account/scope are provider-controlled
 * (account + granted scope come from the OAuth token response / account probe), and the Slack ids
 * are user-controlled, so nothing here may inject markup into this page served on the Vouchr host.
 * The ONE escaper for the callback landing pages, shared by the Bolt route and the headless broker. */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

/**
 * The post-connect browser page, shared by every supported callback surface (the Bolt route and the
 * headless broker) — an adapter-layer HTTP concern, deliberately out of transport-agnostic core.
 *
 * The bound Slack `identity` is REQUIRED: consent binds the *initiating* Slack user, so a forwarded
 * link lets someone else authorize their provider account under that user. The page names the bound
 * user AND links to their Slack profile (a `slack://user` deep link — clickable to a real name and
 * photo, so the completer can actually recognize whether the identity is theirs, which bare `U…`/`T…`
 * ids do not allow). The provider account is shown when known but may be null, so the copy never
 * depends on it. See guides/THREAT-MODEL.md, "Forwarded consent link".
 */
export function connectedHtml(
  provider: string,
  account: string | null,
  scopes: string | undefined,
  identity: SlackIdentity,
): string {
  const p = escapeHtml(provider);
  const who = account ? ` as ${escapeHtml(account)}` : '';
  const acct = account ? ` (${escapeHtml(account)})` : '';
  const withScopes = scopes ? ` with: <code>${escapeHtml(scopes)}</code>` : '';
  // Deep-link to the bound user's Slack profile so the completer can see who it actually is.
  const profileLink = escapeHtml(
    `slack://user?team=${encodeURIComponent(identity.teamId)}&id=${encodeURIComponent(identity.userId)}`,
  );
  return `<!doctype html><html><head><meta charset="utf-8"></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
    <h2>✅ ${p} connected${who}</h2>
    <p style="color:#555">This connection is now linked to <a href="${profileLink}">this Slack user</a> (<code>${escapeHtml(identity.userId)}</code> in workspace <code>${escapeHtml(identity.teamId)}</code>). The agent will act as that Slack user${withScopes}.</p>
    <p style="color:#b00">If that is not your Slack account, you have connected this ${p} account${acct} to someone else — open the link above to check who, then contact your Slack admin.</p>
    <p>You can close this tab.</p>
  </body></html>`;
}
