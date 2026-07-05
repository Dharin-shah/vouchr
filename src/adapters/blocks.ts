import type { AuditRow, StatsRow } from '../core/audit';

/** Escape the three chars Slack mrkdwn treats specially, so a value that reached the audit table can
 *  never render as a link/mention/broadcast. The `provider` column is attacker-controllable (e.g. an
 *  unvalidated `/vouchr configure <arg>` denial writes `arg` there), so an admin's `audit channel`
 *  view must not turn a stored string into a forged `<…|link>` or `<@user>` mention. */
const escapeMrkdwn = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** `/vouchr audit`: a compact, read-only view of credential usage. Renders ONLY the non-secret
 *  columns (provider/action/actor/channel/time) — never `meta`, which the query already omits.
 *  Timestamps use Slack's `<!date^…>` token so each viewer sees their own locale/timezone.
 *  `heading` is caller-supplied constant text, never a stored value — safe as a plain_text header. */
export function auditBlocks(rows: AuditRow[], heading: string): unknown[] {
  if (!rows.length) {
    return [{ type: 'section', text: { type: 'mrkdwn', text: `:information_source: *${heading}*\nNothing recorded yet.` } }];
  }
  const lines = rows.map((r) => {
    const secs = Math.floor(r.at / 1000);
    const when = `<!date^${secs}^{date_short_pretty} {time}|${new Date(r.at).toISOString()}>`;
    // actor/channel are Slack ids wrapped as a mention; escape defensively in case a future record
    // path stores a non-id string, and escape the free-text provider/action columns unconditionally.
    const who = r.actor ? ` · by <@${escapeMrkdwn(r.actor)}>` : '';
    const where = r.channel ? ` · <#${escapeMrkdwn(r.channel)}>` : '';
    return `• *${escapeMrkdwn(r.provider)}* · ${escapeMrkdwn(r.action)}${who}${where} · ${when}`;
  });
  return [
    { type: 'header', text: { type: 'plain_text', text: heading, emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: lines.join('\n') } },
  ];
}

/** `/vouchr stats`: per-provider usage for the channel over the window. Iterates the ENABLED tool list
 *  (not just providers with rows) so an enabled-but-idle tool is surfaced as dead weight to prune. No
 *  secret — injection counts + distinct-actor counts + last-used only. `escapeMrkdwn` guards provider
 *  ids (attacker-controllable via a `configure`-style path) exactly as `auditBlocks` does. */
export function statsBlocks(enabled: string[], stats: StatsRow[], windowDays: number): unknown[] {
  if (!enabled.length) {
    return [{ type: 'section', text: { type: 'mrkdwn', text: ':information_source: *No brokered tools are enabled in this channel.*' } }];
  }
  const byProvider = new Map(stats.map((s) => [s.provider, s]));
  const lines = enabled.map((p) => {
    const s = byProvider.get(p);
    if (!s || s.uses === 0) return `• *${escapeMrkdwn(p)}* — _never used_ (idle; safe to remove)`;
    const when = `<!date^${Math.floor(s.lastUsed / 1000)}^{date_short_pretty}|recently>`;
    const people = s.distinctActors === 1 ? '1 person' : `${s.distinctActors} people`;
    return `• *${escapeMrkdwn(p)}* — ${s.uses} injection${s.uses === 1 ? '' : 's'} · ${people} · last used ${when}`;
  });
  return [
    { type: 'header', text: { type: 'plain_text', text: `Tool usage — last ${windowDays} days`, emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: lines.join('\n') } },
    { type: 'context', elements: [{ type: 'mrkdwn', text: 'Idle tools can be removed with `/vouchr disable <provider>`.' }] },
  ];
}

/** Block Kit for the in-Slack "connect your account" prompt (ephemeral).
 *  `scopes` (optional) lists what the agent will be able to do as you; unknown scope ids
 *  render as their raw string so nothing granted is ever hidden. */
export function connectBlocks(
  provider: string,
  authorizeUrl: string,
  scopes?: { list: string[]; describe?: Record<string, string> },
): unknown[] {
  const blocks: unknown[] = [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:link: *Connect your ${provider} account*\n` +
          `I need to act as you on ${provider} for this. Your token is stored ` +
          `encrypted on this server and is never shown to the agent or posted in Slack.`,
      },
    },
  ];
  if (scopes && scopes.list.length) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          'Connecting grants the agent, acting as you:\n' +
          scopes.list.map((s) => `• ${scopes.describe?.[s] ?? s}`).join('\n'),
      },
    });
  }
  blocks.push({
    type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Connect ${provider}`, emoji: true },
          url: authorizeUrl,
          style: 'primary',
        },
      ],
  });
  return blocks;
}

export const CONFIGURE_CALLBACK = 'vouchr_configure';
export const USER_KEY_CALLBACK = 'vouchr_user_key';
export const SETUP_KEY_ACTION = 'vouchr_setup_key';
export const APPROVE_SESSION_ACTION = 'vouchr_approve_session';

/** The two leak-safe secret-entry fields: an external reference (preferred) OR a raw key. */
function secretFields(): unknown[] {
  return [
    {
      type: 'input',
      optional: true,
      block_id: 'ref',
      label: { type: 'plain_text', text: 'External secret reference' },
      hint: {
        type: 'plain_text',
        text: 'Preferred: an AWS Secrets Manager ARN. Rotation stays in AWS; Vouchr stores only the pointer.',
      },
      element: { type: 'plain_text_input', action_id: 'v', placeholder: { type: 'plain_text', text: 'arn:aws:secretsmanager:…' } },
    },
    {
      type: 'input',
      optional: true,
      block_id: 'raw',
      label: { type: 'plain_text', text: '…or paste a key directly' },
      hint: {
        type: 'plain_text',
        // Note: Block Kit has no masked input. The value is never echoed back, posted, or
        // logged, but a reference is still preferable.
        text: 'Stored encrypted by Vouchr. Use a reference instead when your secret manager can hold it.',
      },
      element: { type: 'plain_text_input', action_id: 'v' },
    },
  ];
}

/**
 * Private secret-entry modal (leak-safe UX). The value typed here lives only in this view,
 * never posted, logged, or put in audit meta. `meta` rides in private_metadata so the submit
 * binds to the right owner (a channel for admin config, or nothing for a per-user key).
 */
function secretModal(o: { callbackId: string; meta: object; title: string; intro: string }): unknown {
  return {
    type: 'modal',
    callback_id: o.callbackId,
    private_metadata: JSON.stringify(o.meta),
    title: { type: 'plain_text', text: o.title },
    submit: { type: 'plain_text', text: 'Save' },
    close: { type: 'plain_text', text: 'Cancel' },
    blocks: [{ type: 'section', text: { type: 'mrkdwn', text: o.intro } }, ...secretFields()],
  };
}

/** Admin modal: set the CHANNEL's shared credential (invariant 7, admin-gated upstream). */
export function configureModal(provider: string, channel: string): unknown {
  return secretModal({
    callbackId: CONFIGURE_CALLBACK,
    meta: { channel, provider },
    title: 'Channel credential',
    intro:
      `Set the *${provider}* credential for this channel. Only you can see what you ` +
      `type here. It is never posted to the channel.`,
  });
}

/** Self-service modal: a user sets their OWN credential for a key-based provider. */
export function userKeyModal(provider: string): unknown {
  return secretModal({
    callbackId: USER_KEY_CALLBACK,
    meta: { provider },
    title: 'Your credential',
    intro:
      `Set your own *${provider}* key. Only you can see this; it is stored encrypted and used ` +
      `only when you ask the agent, never shown to the agent or posted in Slack.`,
  });
}

/** Ephemeral JIT prompt: a button that opens the per-user key modal (for key providers). */
export function keySetupBlocks(provider: string): unknown[] {
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:key: *Set up your ${provider} access*\n` +
          `I need a ${provider} key to act for you. Add yours. It is stored encrypted on this ` +
          `server and is never shown to the agent or posted in Slack.`,
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Set up ${provider}`, emoji: true },
          action_id: SETUP_KEY_ACTION,
          value: provider,
          style: 'primary',
        },
      ],
    },
  ];
}

/** Ephemeral in-thread prompt: a button granting the agent use of `provider` for THIS thread only.
 *  `thread` is carried in the button value so the action handler grants the exact thread. */
export function sessionApprovalBlocks(provider: string, thread: string): unknown[] {
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:lock: *Allow ${provider} in this thread?*\n` +
          `The agent will be able to act as you on ${provider} only inside this thread, until the ` +
          `session expires. This approval does not apply to any other thread or channel.`,
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Allow ${provider} here`, emoji: true },
          action_id: APPROVE_SESSION_ACTION,
          value: JSON.stringify({ provider, thread }),
          style: 'primary',
        },
      ],
    },
  ];
}

export const DISCONNECT_ACTION = 'vouchr_disconnect';

/** One connection row for the status / home views. `channel` null = a personal (DM) credential. */
export type Connection = { provider: string; channel: string | null; mode?: string };

/** A readable line for one connection, reused by the status list and the App Home tab. */
function connectionLine(c: Connection): string {
  const where = c.channel ? `<#${c.channel}>` : 'your DMs';
  const mode = c.mode ? ` — _${c.mode}_` : '';
  return `• *${c.provider}* in ${where}${mode}`;
}

/** DM shown after a user successfully connects a credential: what, where, and how to undo. */
export function connectedBlocks(
  provider: string,
  o: { channel: string | null; scope?: string; account?: string },
): unknown[] {
  const where = o.channel ? `<#${o.channel}>` : 'your DMs';
  const scope = o.scope ? ` (${o.scope})` : '';
  const account = o.account ? `Connected as *${o.account}*.\n` : '';
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:white_check_mark: *${provider} connected*\n` +
          account +
          `Vouchr can now act as you on ${provider} in ${where}${scope}. Your token is stored ` +
          `encrypted and is never shown to the agent or posted in Slack.`,
      },
    },
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `Disconnect any time with \`/vouchr disconnect ${provider}\`.` }],
    },
  ];
}

/** Message shown when a user declines consent (or consent is required and not granted). */
export function consentDeniedBlocks(provider: string, reason?: string): unknown[] {
  const why = reason ?? `You haven't allowed ${provider} for this request.`;
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:no_entry: *${provider} not authorized*\n` +
          `${why} Nothing was sent on your behalf.`,
      },
    },
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `Re-run the request to be prompted again, or connect with \`/vouchr connect ${provider}\`.` }],
    },
  ];
}

/** `/vouchr status`: a user's current connections and per-channel modes. */
export function statusBlocks(connections: Connection[]): unknown[] {
  if (connections.length === 0) {
    return [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: ":information_source: *No connections yet*\nUse `/vouchr connect <provider>` to get started." },
      },
    ];
  }
  return [
    { type: 'header', text: { type: 'plain_text', text: 'Your Vouchr connections', emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: connections.map(connectionLine).join('\n') } },
  ];
}

/** Ephemeral confirm-prompt: a destructive button to disconnect `provider`.
 *  `provider` rides in the button value so the action handler removes the exact credential. */
export function disconnectConfirmBlocks(provider: string): unknown[] {
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:warning: *Disconnect ${provider}?*\n` +
          `Vouchr will delete your stored ${provider} credential. The agent won't be able to act as ` +
          `you on ${provider} until you connect again.`,
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Disconnect ${provider}`, emoji: true },
          action_id: DISCONNECT_ACTION,
          value: provider,
          style: 'danger',
        },
      ],
    },
  ];
}

/** App Home tab: a summary of the user's connections plus providers available to connect. */
export function homeView(o: { connections: Connection[]; providers: string[] }): unknown {
  const connected = new Set(o.connections.map((c) => c.provider));
  const available = o.providers.filter((p) => !connected.has(p));
  const blocks: unknown[] = [
    { type: 'header', text: { type: 'plain_text', text: 'Vouchr', emoji: true } },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: o.connections.length
          ? '*Your connections*\n' + o.connections.map(connectionLine).join('\n')
          : "*Your connections*\nNone yet — connect a provider below to let the agent act as you.",
      },
    },
  ];
  if (available.length) {
    blocks.push({ type: 'divider' });
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: '*Available providers*\n' + available.map((p) => `• ${p}`).join('\n') },
    });
    blocks.push({
      type: 'context',
      elements: [{ type: 'mrkdwn', text: 'Connect with `/vouchr connect <provider>`.' }],
    });
  }
  return { type: 'home', blocks };
}

/** HTML-escape untrusted values before inlining: provider/account/scope can be provider-controlled
 * (account + granted scope come from the OAuth token response / account probe), so a malicious or
 * compromised provider must not be able to inject markup into this page served on the Vouchr host. */
const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);

/** Confirmation HTML shown in the browser tab after a successful connect. */
export function connectedHtml(provider: string, account: string | null, scopes?: string): string {
  const who = account ? ` as ${escapeHtml(account)}` : '';
  const granted = scopes
    ? `<p style="color:#555">The agent can now, acting as you: <code>${escapeHtml(scopes)}</code></p>`
    : '';
  return `<!doctype html><html><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
    <h2>✅ ${escapeHtml(provider)} connected${who}</h2>
    ${granted}
    <p>You can close this tab and return to Slack.</p>
  </body></html>`;
}
