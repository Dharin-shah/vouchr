import type { AuditRow, StatsRow } from '../core/audit';
import { CHANNEL_MODES, isChannelMode } from '../core/channelConfig';

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
    const s = byProvider.get(p); // absent = no injections in the window (a GROUP BY row is always ≥ 1)
    if (!s) return `• *${escapeMrkdwn(p)}* — _never used_ (idle; safe to remove)`;
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

export const PREVIEW_SHARE_ACTION = 'vouchr_preview_share';
export const PREVIEW_DISMISS_ACTION = 'vouchr_preview_dismiss';

/** Slack caps a header at 150 chars and a section at 3000; clip instead of erroring mid-post. */
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Slack rejects an empty text object, and the agent's title/lines are host-supplied: normalize an
 *  empty/blank title to a provider-named one so an otherwise-valid preview never fails at post time. */
const previewTitle = (title: string, provider: string): string => clip(title.trim() || `${provider} preview`, 150);

/** Escaped, length-capped preview body. Every line is provider-derived (user-influenced) text, so
 *  each goes through escapeMrkdwn — a fetched string must never render as a forged link/mention.
 *  '' when there are no (non-blank) lines; callers omit the section entirely (empty text is invalid). */
const previewBody = (lines: string[]): string =>
  clip(lines.filter((l) => l.trim()).map((l) => escapeMrkdwn(l)).join('\n'), 2900);

/**
 * Normalize agent-supplied preview content to what rendering can actually show: blank lines dropped,
 * blank title defaulted, and the SAME length caps the builders apply. Callers that HOLD content (the
 * pending-preview store) normalize first, so nothing a human never saw is retained in memory. Kept
 * beside the render helpers: one owner for the caps. Escaping stays at render (SEC-5), not here.
 */
export function normalizePreviewContent(
  provider: string,
  content: { title: string; lines: string[] },
): { title: string; lines: string[] } {
  const lines: string[] = [];
  let budget = 2900;
  for (const l of content.lines) {
    if (!l.trim()) continue;
    if (budget <= 0) break;
    const kept = clip(l, budget);
    lines.push(kept);
    budget -= kept.length + 1; // +1: the '\n' previewBody joins with
  }
  return { title: previewTitle(content.title, provider), lines };
}

/**
 * Ephemeral PRIVATE preview of provider-derived agent output (channel visibility 'private'): only
 * the requester sees it, with an explicit Share action. `id` is the pending-preview claim id — the
 * ONLY thing the buttons carry (SEC-3: content or authorization in a button value would be forgeable;
 * the handler re-authorizes the claim server-side against the stored recipient).
 */
export function previewBlocks(o: {
  provider: string;
  title: string;
  lines: string[];
  id: string;
  where: 'thread' | 'channel';
  ttlMinutes: number;
}): unknown[] {
  const body = previewBody(o.lines);
  return [
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `:lock: *Private preview* · ${escapeMrkdwn(o.provider)} · only visible to you` }],
    },
    { type: 'header', text: { type: 'plain_text', text: previewTitle(o.title, o.provider), emoji: true } },
    ...(body ? [{ type: 'section', text: { type: 'mrkdwn', text: body } }] : []),
    { type: 'divider' },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Share to ${o.where}`, emoji: true },
          action_id: PREVIEW_SHARE_ACTION,
          value: o.id,
          style: 'primary',
        },
        { type: 'button', text: { type: 'plain_text', text: 'Dismiss', emoji: true }, action_id: PREVIEW_DISMISS_ACTION, value: o.id },
      ],
    },
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `Sharing posts this to the ${o.where}, attributed to you. Expires in ${o.ttlMinutes} minutes.` }],
    },
  ];
}

/**
 * A preview posted PUBLICLY: either directly (channel visibility 'public') or via the requester's
 * Share click (`sharedBy` set — the attribution footer is the transparency half of private mode:
 * the channel always sees WHO decided the data was safe to share).
 */
export function previewPostBlocks(o: { provider: string; title: string; lines: string[]; sharedBy?: string }): unknown[] {
  const footer = o.sharedBy
    ? `:outbox_tray: Shared by <@${escapeMrkdwn(o.sharedBy)}> from a private *${escapeMrkdwn(o.provider)}* preview`
    : `*${escapeMrkdwn(o.provider)}* · via Vouchr`;
  const body = previewBody(o.lines);
  return [
    { type: 'header', text: { type: 'plain_text', text: previewTitle(o.title, o.provider), emoji: true } },
    ...(body ? [{ type: 'section', text: { type: 'mrkdwn', text: body } }] : []),
    { type: 'context', elements: [{ type: 'mrkdwn', text: footer }] },
  ];
}

export const DISCONNECT_ACTION = 'vouchr_disconnect';
export const CONFIG_CALLBACK = 'vouchr_config';

/** The four per-channel auth modes, in the order the config modal lists them. */
/** One connection row for the status / home views. `channel` null = a personal (DM) credential. */
export type Connection = { provider: string; channel: string | null; mode?: string };

/** One provider's read-only channel tool state, for the config modal's "Tools in this channel" list. */
export type ToolRow = { provider: string; enabled: boolean; mode?: string | null; visibility?: string };

/** One provider's admin control row: channel mode (null = unconfigured) + tool-enabled + preview visibility. */
export type ConfigAdminRow = { provider: string; mode: string | null; enabled: boolean; visibility: string };

/**
 * No-arg `/vouchr` config modal (#109). Three sections:
 *  - "Your connections" (EVERYONE): the user's own connections, each with a Disconnect button.
 *  - "Tools in this channel" (EVERYONE): the read-only manifest (which providers are usable here).
 *  - "Channel settings" (ADMINS ONLY, `admin` present): per-provider mode select + Enabled checkbox,
 *    whose submit routes to the SAME mode/enable/disable mutations as the slash commands.
 *
 * The channel rides in `private_metadata` so the submit binds to the right channel. The admin controls'
 * mere presence is NOT the authorization — the submit handler re-checks admin server-side, so a forged
 * submission from a non-admin (who never saw these controls) is still rejected. A `submit` button is
 * only added when there ARE admin controls (otherwise there is nothing to submit; disconnect is an
 * immediate button action, not a form field).
 */
export function configModal(o: {
  channel: string | null;
  connections: Connection[];
  tools: ToolRow[];
  admin?: ConfigAdminRow[];
}): unknown {
  const blocks: unknown[] = [
    { type: 'header', text: { type: 'plain_text', text: 'Your connections', emoji: true } },
  ];
  if (o.connections.length) {
    for (const c of o.connections) {
      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: connectionLine(c) },
        accessory: {
          type: 'button',
          text: { type: 'plain_text', text: 'Disconnect', emoji: true },
          action_id: DISCONNECT_ACTION,
          value: c.provider,
          style: 'danger',
          // Destructive + one-click, so gate it behind a native confirm dialog (parity with the
          // ephemeral `/vouchr disconnect` confirm flow) — an accidental click shouldn't revoke.
          confirm: {
            title: { type: 'plain_text', text: 'Disconnect?' },
            text: { type: 'mrkdwn', text: `Vouchr will delete your stored *${escapeMrkdwn(c.provider)}* credential. The agent won't be able to act as you on ${escapeMrkdwn(c.provider)} until you connect again.` },
            confirm: { type: 'plain_text', text: 'Disconnect' },
            deny: { type: 'plain_text', text: 'Cancel' },
            style: 'danger',
          },
        },
      });
    }
  } else {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: 'No connected accounts yet. They are created on demand when an agent needs one.' }] });
  }

  blocks.push({ type: 'divider' });
  blocks.push({ type: 'header', text: { type: 'plain_text', text: 'Tools in this channel', emoji: true } });
  if (!o.channel) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: 'Open `/vouchr` from inside a channel to see and configure its tools.' }] });
  } else if (!o.tools.length) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: 'No providers are registered.' }] });
  } else {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: o.tools.map((t) => `• *${escapeMrkdwn(t.provider)}*: ${t.enabled ? 'enabled' : 'disabled'}${t.mode ? ` (${escapeMrkdwn(t.mode)})` : ''}${t.visibility === 'private' ? ' · :lock: private previews' : ''}`).join('\n') },
    });
  }

  if (o.admin && o.admin.length) {
    blocks.push({ type: 'divider' });
    blocks.push({ type: 'header', text: { type: 'plain_text', text: 'Channel settings (admin)', emoji: true } });
    for (const p of o.admin) {
      // Mode select — block_id `mode:<provider>` so the submit maps it back. Optional + initial set to
      // the current mode. The submit diffs against the OPEN-TIME value carried in private_metadata (not a
      // re-read of the store), so an untouched select never mutates and never reverts a concurrent change.
      const modeOptions = CHANNEL_MODES.map((m) => ({ text: { type: 'plain_text', text: m }, value: m }));
      const initialMode = isChannelMode(p.mode) ? modeOptions.find((x) => x.value === p.mode) : undefined;
      blocks.push({
        type: 'input',
        optional: true,
        block_id: `mode:${p.provider}`,
        label: { type: 'plain_text', text: `${p.provider} — mode` },
        element: {
          type: 'static_select',
          action_id: 'mode',
          options: modeOptions,
          ...(initialMode ? { initial_option: initialMode } : {}),
        },
      });
      const enabledOption = { text: { type: 'plain_text', text: 'Enabled in this channel' }, value: 'enabled' };
      blocks.push({
        type: 'input',
        optional: true,
        block_id: `tool:${p.provider}`,
        label: { type: 'plain_text', text: `${p.provider} — availability` },
        element: {
          type: 'checkboxes',
          action_id: 'enabled',
          options: [enabledOption],
          ...(p.enabled ? { initial_options: [enabledOption] } : {}),
        },
      });
      // Preview visibility — same open-time-diff contract as the mode select (block_id `preview:<provider>`).
      const privateOption = {
        text: { type: 'plain_text', text: 'Private previews' },
        description: { type: 'plain_text', text: 'Results go only to the requester, with a Share button.' },
        value: 'private',
      };
      blocks.push({
        type: 'input',
        optional: true,
        block_id: `preview:${p.provider}`,
        label: { type: 'plain_text', text: `${p.provider} — preview visibility` },
        element: {
          type: 'checkboxes',
          action_id: 'visibility',
          options: [privateOption],
          ...(p.visibility === 'private' ? { initial_options: [privateOption] } : {}),
        },
      });
    }
  }

  // Carry the channel AND the OPEN-TIME admin state (compact keys: p/m/e) so the submit can tell a
  // deliberately-changed control from an untouched one that merely re-submits its initial value — the
  // basis for not reverting a concurrent admin's change and not writing spurious rows. Non-secret.
  const open = (o.admin ?? []).map((p) => ({ p: p.provider, m: p.mode, e: p.enabled, v: p.visibility }));
  return {
    type: 'modal',
    callback_id: CONFIG_CALLBACK,
    private_metadata: JSON.stringify({ channel: o.channel, open }),
    title: { type: 'plain_text', text: 'Vouchr' },
    ...(o.admin && o.admin.length ? { submit: { type: 'plain_text', text: 'Save' } } : {}),
    close: { type: 'plain_text', text: 'Close' },
    blocks,
  };
}

/** A readable line for one connection, reused by the status list and the App Home tab. */
function connectionLine(c: Connection): string {
  // Escape provider/channel/mode before they hit mrkdwn: a stored provider id is attacker-influenceable
  // (see escapeMrkdwn's note), so no value here may render as a forged `<…|link>` or `<@user>` mention.
  const where = c.channel ? `<#${escapeMrkdwn(c.channel)}>` : 'your DMs';
  const mode = c.mode ? ` — _${escapeMrkdwn(c.mode)}_` : '';
  return `• *${escapeMrkdwn(c.provider)}* in ${where}${mode}`;
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
