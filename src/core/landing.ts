import type { SlackIdentity } from './identity';

/** HTML-escape untrusted values before inlining: provider/account/scope are provider-controlled
 * (account + granted scope come from the OAuth token response / account probe), and the Slack ids
 * are user-controlled, so nothing here may inject markup into this page served on the Vouchr host. */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

/**
 * The post-connect browser page, shared by every supported callback surface (Bolt route + headless
 * broker). The bound Slack `identity` is REQUIRED: consent binds the *initiating* Slack user, so a
 * forwarded link lets someone else authorize their provider account under that user. Naming both the
 * concrete provider account (the human-recognizable anchor) and the bound Slack user/workspace is
 * the only signal the completer gets that a forwarded link empowered someone else's agent — so it
 * cannot be an optional branch (see guides/THREAT-MODEL.md, "Forwarded consent link").
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
  return `<!doctype html><html><head><meta charset="utf-8"></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
    <h2>✅ ${p} connected${who}</h2>
    <p style="color:#555">This connection is now linked to Slack user <code>${escapeHtml(identity.userId)}</code> in workspace <code>${escapeHtml(identity.teamId)}</code>. The agent will act as that Slack user${withScopes}.</p>
    <p style="color:#b00">If that Slack user is not you, you have connected your ${p} account${acct} to someone else — contact your Slack admin.</p>
    <p>You can close this tab.</p>
  </body></html>`;
}
