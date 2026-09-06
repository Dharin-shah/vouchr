import type { AuditRow, StatsRow } from '../core/audit';
import { CHANNEL_IDENTITIES, isChannelIdentity, type ChannelIdentity } from '../core/channelConfig';
import { isBrokeredProvider, type ApprovalGrant, type Approver } from '../core/providers';
import { SECRET_REFERENCE_SOURCES, type SecretReferenceSource } from '../core/reference';
import type { VouchrRecovery } from '../core/errors';
import type { AttributedOAuthCallbackOutcome } from '../core/oauthCallback';
import { STATE_TTL_US } from '../core/consent';
import { PENDING_INTERACTION_TTL_US } from '../core/interaction';

/** Every prompt states its own lifetime from the constant that enforces it (STR-2, #348). */
const minutes = (us: number): string => `${Math.round(us / 60_000_000)} minutes`;
const CONNECT_PROMPT_LIFETIME = minutes(STATE_TTL_US);
const PENDING_PROMPT_LIFETIME = minutes(PENDING_INTERACTION_TTL_US);

/** Escape the three chars Slack mrkdwn treats specially, so a value that reached the audit table can
 *  never render as a link/mention/broadcast. The `provider` column is attacker-controllable (e.g. an
 *  unvalidated `/vouchr connect-shared <arg>` denial writes `arg` there), so a member's `audit channel`
 *  view must not turn a stored string into a forged `<…|link>` or `<@user>` mention. */
export const escapeMrkdwn = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Slack's hard bounds for one mrkdwn section and a top-level message fallback. The latter is the
 *  truncation boundary documented by Slack, so fail before a caller posts a partial accessibility
 *  description. */
const SLACK_SECTION_TEXT_MAX = 3000;
const SLACK_TOP_LEVEL_TEXT_MAX = 40_000;
const SLACK_VIEW_PRIVATE_METADATA_MAX = 3000;

type SectionPackOptions = {
  firstPrefix?: string;
  continuationPrefix?: string;
  maxSections?: number;
  sectionError?: string;
  blockError?: string;
};

/** Pack complete, already-rendered rows into Slack-valid mrkdwn sections. Rows are never clipped,
 *  split, or dropped: an individually oversized row (or an excessive section count) is rejected so
 *  the caller can fail visibly rather than post a misleading partial table. */
function mrkdwnSections(lines: string[], o: SectionPackOptions = {}): unknown[] {
  if (!lines.length) return [];
  const sectionError = o.sectionError ?? 'Rendered row exceeds the Slack section limit.';
  const blockError = o.blockError ?? 'Rendered rows exceed the Slack block limit.';
  const sections: string[] = [];
  let current = o.firstPrefix ?? '';

  for (const line of lines) {
    const candidate = current ? `${current}\n${line}` : line;
    if (candidate.length <= SLACK_SECTION_TEXT_MAX) {
      current = candidate;
      continue;
    }
    // A prefix with no row is not useful content; if even the first row cannot fit beside it,
    // reject it instead of emitting a prefix-only section or splitting the row.
    if (!current || current === o.firstPrefix) throw new Error(sectionError);
    sections.push(current);
    current = o.continuationPrefix ? `${o.continuationPrefix}\n${line}` : line;
    if (current.length > SLACK_SECTION_TEXT_MAX) throw new Error(sectionError);
  }
  if (current) sections.push(current);
  if (o.maxSections !== undefined && sections.length > o.maxSections) throw new Error(blockError);
  return sections.map((text) => ({ type: 'section', text: { type: 'mrkdwn', text } }));
}

/** One mrkdwn context block: the small note under a section. */
function contextBlock(text: string): unknown {
  return { type: 'context', elements: [{ type: 'mrkdwn', text }] };
}

/** Build the parsed top-level `text` Slack uses for notifications and screen readers from exactly
 *  the copy displayed in supported message blocks. Only visible text is read: URLs, action values,
 *  metadata, input fields, and other payload data are deliberately ignored. `plain_text` labels are
 *  escaped because the resulting top-level string is parsed as mrkdwn; mrkdwn copy was escaped by
 *  its renderer already. */
export function blocksFallbackText(blocks: unknown[]): string {
  const out: string[] = [];
  const addText = (value: unknown): void => {
    if (!value || typeof value !== 'object') return;
    const text = value as { type?: unknown; text?: unknown };
    if (typeof text.text !== 'string' || !text.text) return;
    if (text.type === 'mrkdwn') out.push(text.text);
    else if (text.type === 'plain_text') out.push(escapeMrkdwn(text.text));
  };
  const addActionLabel = (value: unknown): void => {
    if (!value || typeof value !== 'object') return;
    addText((value as { text?: unknown }).text);
  };

  for (const value of blocks) {
    if (!value || typeof value !== 'object') continue;
    const block = value as {
      type?: unknown;
      text?: unknown;
      fields?: unknown;
      elements?: unknown;
      accessory?: unknown;
    };
    if (block.type === 'header') {
      addText(block.text);
    } else if (block.type === 'section') {
      addText(block.text);
      if (Array.isArray(block.fields)) for (const field of block.fields) addText(field);
      addActionLabel(block.accessory);
    } else if (block.type === 'context') {
      if (Array.isArray(block.elements)) for (const element of block.elements) addText(element);
    } else if (block.type === 'actions') {
      if (Array.isArray(block.elements)) for (const element of block.elements) addActionLabel(element);
    }
  }

  const fallback = out.join('\n');
  if (!fallback) throw new Error('Slack fallback text has no visible block copy.');
  if (fallback.length > SLACK_TOP_LEVEL_TEXT_MAX) {
    throw new Error('Slack fallback text exceeds the top-level message limit.');
  }
  return fallback;
}

/** `/vouchr audit`: a compact, read-only view of credential usage. Renders ONLY the non-secret
 *  columns (provider/action/actor/channel/time) — never `meta`, which the query already omits.
 *  Timestamps use Slack's `<!date^…>` token so each viewer sees their own locale/timezone.
 *  `heading` is caller-supplied constant text, never a stored value — safe as a plain_text header. */
export function auditBlocks(rows: AuditRow[], heading: string): unknown[] {
  if (!rows.length) {
    return [{ type: 'section', text: { type: 'mrkdwn', text: `:information_source: *${escapeMrkdwn(heading)}*\nNothing recorded yet.` } }];
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
    ...mrkdwnSections(lines, { maxSections: 49 }),
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
    ...mrkdwnSections(lines, { maxSections: 48 }),
    contextBlock('Idle tools can be removed with `/vouchr disable <provider>`.'),
  ];
}

/** Block Kit for the in-Slack "connect your account" prompt (ephemeral).
 *  `scopes` (optional) lists what the agent will be able to do as you; unknown scope ids
 *  render as their raw string so nothing granted is ever hidden. `state` (#347) rides in the
 *  button value so the click handler can replace the prompt in place; it carries no authority
 *  (the handler re-reads the row and never spends it). REQUIRED: every rendered button must be
 *  addressable, so the browser's "the prompt in Slack now offers a new link" is always true. */
export function connectBlocks(
  provider: string,
  authorizeUrl: string,
  scopes: { list: string[]; describe?: Record<string, string> } | undefined,
  state: string,
): unknown[] {
  const MAX_SCOPE_SECTIONS = 48; // intro + scope sections + actions must stay within 50 message blocks
  // SEC-5 (#178): escape the provider id like every other mrkdwn renderer — no exception for a
  // registry-validated id. One escape site, used everywhere `provider` hits mrkdwn below.
  const p = escapeMrkdwn(provider);
  const blocks: unknown[] = [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:link: *Connect your ${p} account*\n` +
          `I need to act as you on ${p} for this. Your token is stored ` +
          `encrypted on this server and is never shown to the agent or posted in Slack. ` +
          `This link expires in ${CONNECT_PROMPT_LIFETIME}.`,
      },
    },
  ];
  if (scopes && scopes.list.length) {
    const lines = scopes.list.map((s) => {
      // Both values are provider configuration and therefore user-influenced. Keep the renderer
      // safe even when called directly, and do not let a blank description hide the actual scope.
      const description = scopes.describe?.[s];
      const label = typeof description === 'string' && description.trim() ? description : s;
      return `• ${escapeMrkdwn(label)}`;
    });
    blocks.push(...mrkdwnSections(lines, {
      firstPrefix: 'Connecting grants the agent, acting as you:',
      continuationPrefix: 'Additional granted scopes:',
      maxSections: MAX_SCOPE_SECTIONS,
      sectionError: 'Provider scope copy exceeds the Slack section limit.',
      blockError: 'Provider scopes exceed the Slack message block limit.',
    }));
  }
  blocks.push({
    type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Connect ${provider}`, emoji: true },
          url: authorizeUrl,
          // Slack sends a block_actions payload for url buttons too; without an action_id + registered
          // ack the client shows "Operation timed out". The action carries no authority (SEC-3).
          action_id: OAUTH_CONNECT_ACTION,
          value: state,
          style: 'primary',
        },
      ],
  });
  return blocks;
}

/** The fixed Slack-side copy for a Connect click Vouchr cannot map to the clicker's own row (#347):
 *  unknown, finalized, swept, tampered, or another user's state. The browser verify hop renders the
 *  same sentence (`src/adapters/slackVerify.ts`), so both surfaces agree. */
export const CONNECT_PROMPT_STALE_TEXT =
  'This connection request is no longer current. Ask the agent for a new connection prompt.';
/** Replaces an in-channel Connect ephemeral once its live link has been opened (#347). */
export const CONNECT_PROMPT_OPENING_TEXT =
  'Opening the sign-in page. If it says the request is no longer current, mention me again.';

/** In-place replacement for a Connect prompt whose state expired, was superseded, or was spent
 *  (#347). The button carries only the old opaque state: the handler re-resolves owner, provider,
 *  and channel from that row and mints the next generation under the delivery lease. */
export function connectExpiredBlocks(provider: string, state: string): unknown[] {
  const p = escapeMrkdwn(provider);
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:link: *Connect your ${p} account*\n` +
          'This connection prompt is no longer current. Get a new link to continue.',
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: 'Send a new link', emoji: true },
          action_id: OAUTH_RENEW_ACTION,
          value: state,
          style: 'primary',
        },
      ],
    },
  ];
}

export const CONFIGURE_CALLBACK = 'vouchr_configure';
export const USER_KEY_CALLBACK = 'vouchr_user_key';
export const SETUP_KEY_ACTION = 'vouchr_setup_key';
/** The OAuth "Connect <provider>" button. It carries a `url` (opens the provider's authorize page
 *  directly), but Slack STILL delivers a block_actions interaction for a url button — so the button
 *  needs an action_id and the host must register a no-op ack, or Slack shows "Operation timed out.
 *  Apps need to respond within 3 seconds." No id/authority rides in the button; the OAuth `state` in
 *  the url is the only carrier. */
export const OAUTH_CONNECT_ACTION = 'vouchr_oauth_connect';
/** "Send a new link" on a replaced stale Connect prompt (#347). Value: the old opaque state. */
export const OAUTH_RENEW_ACTION = 'vouchr_oauth_renew';
/** Legacy #117 action id. New health DMs render no long-lived reconnect control; the registered
 * handler only acknowledges already-delivered buttons with fixed stale guidance. */
export const RECONNECT_ACTION = 'vouchr_reconnect';

const REFERENCE_COPY: Record<SecretReferenceSource, { label: string; placeholder: string }> = {
  'aws-sm': { label: 'AWS Secrets Manager ARN', placeholder: 'arn:aws:secretsmanager:…' },
  'gcp-sm': { label: 'GCP Secret Manager', placeholder: 'gcp-sm://projects/…/versions/latest' },
  'azure-kv': { label: 'Azure Key Vault', placeholder: 'azure-kv://vault-name/secret-name' },
  vault: { label: 'HashiCorp Vault', placeholder: 'vault://mount/path#field' },
};

/** The leak-safe secret-entry fields. A reference is offered only when this Bolt process has a
 * matching resolver; otherwise the modal truthfully presents raw-key storage as the only path. */
function secretFields(referenceSources: readonly SecretReferenceSource[]): unknown[] {
  const configured = SECRET_REFERENCE_SOURCES.filter((source) => referenceSources.includes(source));
  const fields: unknown[] = [];
  if (configured.length) {
    fields.push({
      type: 'input',
      optional: true,
      block_id: 'ref',
      label: { type: 'plain_text', text: 'External secret reference' },
      hint: {
        type: 'plain_text',
        text: `Preferred. Available here: ${configured.map((source) => REFERENCE_COPY[source].label).join(', ')}. Vouchr stores only the pointer.`,
      },
      element: {
        type: 'plain_text_input',
        action_id: 'v',
        placeholder: {
          type: 'plain_text',
          text: configured.length === 1 ? REFERENCE_COPY[configured[0]].placeholder : 'Paste a supported reference',
        },
      },
    });
  }
  fields.push({
    type: 'input',
    optional: true,
    block_id: 'raw',
    label: { type: 'plain_text', text: configured.length ? '…or paste a key directly' : 'Paste a key directly' },
    hint: {
      type: 'plain_text',
      // Note: Block Kit has no masked input. The value is never echoed back, posted, or
      // logged, but a reference is still preferable when a resolver is available.
      text: configured.length
        ? 'Stored encrypted by Vouchr. Use a reference instead when your secret manager can hold it.'
        : 'Stored encrypted by Vouchr. The value is never posted or shown to the agent.',
    },
    element: { type: 'plain_text_input', action_id: 'v' },
  });
  return fields;
}

/**
 * Private secret-entry modal (leak-safe UX). The value typed here lives only in this view,
 * never posted, logged, or put in audit meta. `meta` rides in private_metadata so the submit
 * binds to the right owner (a channel for shared-credential config, or nothing for a per-user key).
 */
function secretModal(o: {
  callbackId: string;
  meta: object;
  title: string;
  intro: string;
  referenceSources: readonly SecretReferenceSource[];
}): unknown {
  return {
    type: 'modal',
    callback_id: o.callbackId,
    private_metadata: JSON.stringify(o.meta),
    title: { type: 'plain_text', text: o.title },
    submit: { type: 'plain_text', text: 'Save' },
    close: { type: 'plain_text', text: 'Cancel' },
    blocks: [{ type: 'section', text: { type: 'mrkdwn', text: o.intro } }, ...secretFields(o.referenceSources)],
  };
}

/** Private acknowledgement/result surface for work that must continue after Slack's 3s deadline. */
export function privateStatusModal(title: string, text: string): unknown {
  return {
    type: 'modal',
    title: { type: 'plain_text', text: title },
    close: { type: 'plain_text', text: 'Close' },
    blocks: [{ type: 'section', text: { type: 'mrkdwn', text } }],
  };
}

/** Channel-member modal: set the CHANNEL's shared credential (invariant 7, member-gated upstream). */
export function configureModal(
  provider: string,
  channel: string,
  referenceSources: readonly SecretReferenceSource[] = SECRET_REFERENCE_SOURCES,
  requestId?: string,
  /** When the provider is DISABLED in this channel, warn that the credential is inert until enabled
   *  (a member may still pre-configure). Prevents a "configured but unusable" surprise. */
  disabled = false,
): unknown {
  const p = escapeMrkdwn(provider);
  const warning = disabled
    ? `:warning: *${p}* is currently *disabled* in this channel — a credential set here will NOT be ` +
      `used by the agent until you enable it (\`/vouchr enable ${p}\`).\n\n`
    : '';
  return secretModal({
    callbackId: CONFIGURE_CALLBACK,
    // Built-in Slack flows carry only the opaque request id. Preserve the legacy metadata shape
    // when hosts call this exported renderer directly without the request-backed dispatcher.
    meta: requestId === undefined ? { channel, provider } : { requestId },
    title: 'Channel credential',
    referenceSources,
    intro:
      warning +
      `Set the *${p}* credential for this channel. Only you can see what you ` +
      `type here. It is never posted to the channel.`,
  });
}

/** Self-service modal: a user sets their OWN credential for a key-based provider. */
export function userKeyModal(
  provider: string,
  referenceSources: readonly SecretReferenceSource[] = SECRET_REFERENCE_SOURCES,
  requestId?: string,
): unknown {
  const p = escapeMrkdwn(provider);
  return secretModal({
    callbackId: USER_KEY_CALLBACK,
    meta: { provider, ...(requestId === undefined ? {} : { requestId }) },
    title: 'Your credential',
    referenceSources,
    intro:
      `Set your own *${p}* key. Only you can see this; it is stored encrypted and used ` +
      `only when you ask the agent, never shown to the agent or posted in Slack.`,
  });
}

/** Ephemeral JIT prompt: its button carries only the opaque, actor/provider-bound request id. */
export function keySetupBlocks(provider: string, requestId: string): unknown[] {
  const p = escapeMrkdwn(provider);
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:key: *Set up your ${p} access*\n` +
          `I need a ${p} key to act for you. Add yours. It is stored encrypted on this ` +
          `server and is never shown to the agent or posted in Slack. ` +
          `This prompt expires in ${PENDING_PROMPT_LIFETIME}.`,
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Set up ${provider}`, emoji: true },
          action_id: SETUP_KEY_ACTION,
          value: requestId,
          style: 'primary',
        },
      ],
    },
  ];
}

export const APPROVAL_APPROVE_ACTION = 'vouchr_approval_approve';
export const APPROVAL_DENY_ACTION = 'vouchr_approval_deny';

/** Percent-encode the one byte Slack reads as a label separator inside `<url>`, then escape like
 *  every other mrkdwn value. The result is what a click opens; the link was validated as https. */
function mrkdwnLink(href: string): string {
  return `<${escapeMrkdwn(href.replace(/\|/g, '%7C'))}>`;
}

/** Plain human copy for a grant's lifetime: whole minutes when it divides, else seconds. */
export function grantLifetime(ttlMs: number): string {
  const seconds = Math.round(ttlMs / 1000);
  if (seconds >= 60 && seconds % 60 === 0) {
    const minutes = seconds / 60;
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }
  return `${seconds} second${seconds === 1 ? '' : 's'}`;
}

/** One-line summary of what approving covers (#350). Shared by the prompt and the approve receipt
 *  so the two can never describe the same grant differently. */
export function grantCovers(provider: string, grant: ApprovalGrant, ttlMs: number): string {
  const p = escapeMrkdwn(provider);
  return grant === 'thread'
    ? `This covers every ${p} call that needs approval in this thread for ${grantLifetime(ttlMs)}.`
    : `This covers one call, once, within ${grantLifetime(ttlMs)}.`;
}

/**
 * Approve/Deny prompt for ONE action (#113, #350). It says who asked, the provider, the method and
 * path (plain), the agent's reason and link when given, and what approving covers. The query string
 * is never shown (its names and values are caller-controlled and can carry tokens or PII, SEC-1);
 * it is bound byte-for-byte in the stored digest. The request body is likewise never shown. The
 * buttons carry ONLY the pending-approval id: content or authority in a button value would be
 * forgeable (SEC-3); the click handler re-validates the provider against the registry and re-checks
 * approver eligibility server-side. Every interpolated value is escaped at render (SEC-5); the path,
 * reason, and link render as `plain_text`/an escaped link, never as mrkdwn markup.
 */
export function approvalBlocks(o: {
  provider: string;
  method: string;
  host: string;
  path: string;
  requester: string;
  id: string;
  approver: Approver;
  grant: ApprovalGrant;
  ttlMs: number;
  reason?: string | null;
  link?: string | null;
  /** #360 a worker's request: `unbound` asks any member to authorize it with their own account;
   * `bound` asks the member whose session this thread is. Absent for an ordinary request. */
  delegated?: 'unbound' | 'bound';
}): unknown[] {
  const p = escapeMrkdwn(o.provider);
  const requester = `<@${escapeMrkdwn(o.requester)}>`;
  const intro = o.delegated === 'unbound'
    ? `The worker ${requester} wants to run an action on ${p} and has no account of its own. A member of this channel can authorize it with their own account; the call then runs as that member, once.`
    : o.delegated === 'bound'
      ? `The worker ${requester} wants to run another action on ${p} in this thread, where you authorized it with your account. It runs as you, once, if you approve.`
      : o.approver === 'member'
        ? `The agent wants to run an action on ${p} for ${requester}. Another member of this channel must approve it.`
        : `The agent wants to run an action as you on ${p}.`;
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `:lock: *${o.delegated === 'unbound' ? 'Authorize' : 'Approve'} this ${p} action?*\n${intro}`,
      },
    },
    // The action, plain: method, host, and the exact path. Plain text (never mrkdwn) so a crafted
    // path cannot render links, mentions, or formatting that impersonates Vouchr's copy.
    {
      type: 'section',
      text: { type: 'plain_text', text: `${o.method} ${o.host}${o.path}`, emoji: false },
    },
    ...(o.reason
      ? [{ type: 'section', text: { type: 'plain_text', text: `Reason: ${o.reason}`, emoji: false } }]
      : []),
    ...(o.link
      ? [{ type: 'section', text: { type: 'mrkdwn', text: `Link: ${mrkdwnLink(o.link)}` } }]
      : []),
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `${grantCovers(o.provider, o.grant, o.ttlMs)} This prompt expires in ${PENDING_PROMPT_LIFETIME} if unused. The request body is not shown or inspected.${o.reason || o.link ? ' The reason and link are the agent\u2019s own claim, not verified by Vouchr.' : ''}`,
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: o.delegated === 'unbound' ? 'Authorize with your account' : 'Approve', emoji: true },
          action_id: APPROVAL_APPROVE_ACTION,
          value: o.id,
          style: 'primary',
        },
        {
          type: 'button',
          text: { type: 'plain_text', text: 'Deny', emoji: true },
          action_id: APPROVAL_DENY_ACTION,
          value: o.id,
          style: 'danger',
        },
      ],
    },
  ];
}

export const DISCONNECT_ACTION = 'vouchr_disconnect';
export const CONFIG_CALLBACK = 'vouchr_config';

/** One connection row for the status / home views. `channel` null = a personal (DM) credential.
 *  `account` is the provider-reported external account (escaped at render, provider-influenced).
 *  Vouchr-owned interactive views add the opaque `credentialId`; keeping it optional preserves the
 *  existing exported renderer input shape, while the built-in action handler refuses that fallback. */
export type Connection = {
  provider: string;
  channel: string | null;
  account?: string | null;
  credentialId?: string;
};

/** One provider's read-only channel tool state, for the config modal's "Tools in this channel" list:
 *  usable here or not, and who the agent acts as (see ToolManifestEntry.identity). */
export type ToolRow = { provider: string; enabled: boolean; identity?: ChannelIdentity | 'service' };

/** One provider's governance control row: who the agent acts as + tool-enabled. A 'service' row
 *  gets only the Enable/Disable control (identity/credential mutations are refused by core for it). */
export type ConfigMemberRow = {
  provider: string;
  identity: ChannelIdentity | 'service';
  enabled: boolean;
};

/** The two answers to "Who does the agent act as here?", in the order every picker lists them. */
const IDENTITY_OPTIONS: { text: { type: 'plain_text'; text: string }; value: ChannelIdentity }[] = [
  { text: { type: 'plain_text', text: 'Each member, as themselves' }, value: 'person' },
  { text: { type: 'plain_text', text: 'This channel, with one shared credential' }, value: 'channel' },
];
const identityOption = (identity: unknown) => IDENTITY_OPTIONS.find((o) => isChannelIdentity(identity) && o.value === identity);
// Both pickers list exactly the core enum, so a value the guard refuses can never be offered.
if (IDENTITY_OPTIONS.length !== CHANNEL_IDENTITIES.length) throw new Error('identity picker drifted from CHANNEL_IDENTITIES');

const CONFIG_CONNECTION_ROWS_MAX = 10;

/**
 * No-arg `/vouchr` config modal (#109). Three sections:
 *  - "Your connections" (EVERYONE): a bounded first set with Disconnect buttons, plus explicit
 *    `/vouchr status [page]` guidance when more rows exist.
 *  - "Tools in this channel" (EVERYONE): the read-only manifest (which providers are usable here).
 *  - "Channel settings" (CHANNEL MEMBERS ONLY, `admin` rows present): enabled providers first, each
 *    with a "who does the agent act as here?" select showing the effective identity plus the Enabled
 *    checkbox; disabled providers after, with the checkbox only ("enable to configure"). The submit
 *    routes to the SAME identity/enable/disable mutations as the slash commands.
 *
 * The channel rides in `private_metadata` so the submit binds to the right channel. The governance
 * controls' mere presence is NOT the authorization — the submit handler re-checks membership
 * server-side, so a forged submission from a non-member (who never saw these controls) is still
 * rejected. A `submit` button is only added when there ARE governance controls (otherwise there is
 * nothing to submit; disconnect is an immediate button action, not a form field).
 */
export function configModal(o: {
  channel: string | null;
  connections: Connection[];
  tools: ToolRow[];
  admin?: ConfigMemberRow[];
}): unknown {
  const blocks: unknown[] = [
    { type: 'header', text: { type: 'plain_text', text: 'Your connections', emoji: true } },
  ];
  if (o.connections.length) {
    for (const c of o.connections.slice(0, CONFIG_CONNECTION_ROWS_MAX)) blocks.push(connectionRow(c));
    if (o.connections.length > CONFIG_CONNECTION_ROWS_MAX) {
      blocks.push(contextBlock(`+${o.connections.length - CONFIG_CONNECTION_ROWS_MAX} more — use \`/vouchr status\` to browse every connection, then \`/vouchr disconnect <provider>\`.`));
    }
  } else {
    blocks.push(contextBlock('No connected accounts yet. They are created on demand when an agent needs one.'));
  }

  blocks.push({ type: 'divider' });
  blocks.push({ type: 'header', text: { type: 'plain_text', text: 'Tools in this channel', emoji: true } });
  if (!o.channel) {
    blocks.push(contextBlock('Open `/vouchr` from inside a channel to see and configure its tools.'));
  } else if (!o.tools.length) {
    blocks.push(contextBlock('No providers are registered.'));
  } else {
    blocks.push(...mrkdwnSections(o.tools.map((t) => `• *${escapeMrkdwn(t.provider)}*: ${t.enabled ? 'enabled' : 'disabled'}${t.identity ? ` (${escapeMrkdwn(t.identity)})` : ''}`), { maxSections: 96 }));
  }

  if (o.admin && o.admin.length) {
    blocks.push({ type: 'divider' });
    blocks.push({ type: 'header', text: { type: 'plain_text', text: 'Channel settings', emoji: true } });
    // Enabled providers first, each with its identity line; disabled ones after, with only the enable
    // toggle (#356). The identity select's initial is the EFFECTIVE identity (`person` unless the channel
    // stored `channel`), never blank, so the input is not `optional`.
    const enabledOption = { text: { type: 'plain_text', text: 'Enabled in this channel' }, value: 'enabled' };
    for (const p of [...o.admin.filter((r) => r.enabled), ...o.admin.filter((r) => !r.enabled)]) {
      // block_id `identity:<provider>` so the submit maps it back. The submit diffs against the OPEN-TIME
      // value carried in private_metadata (not a re-read of the store), so an untouched select never
      // mutates and never reverts a concurrent change. A service tool has no identity to pick.
      const initialIdentity = p.enabled ? identityOption(p.identity) : undefined;
      if (initialIdentity) {
        blocks.push({
          type: 'input',
          block_id: `identity:${p.provider}`,
          label: { type: 'plain_text', text: `${p.provider}: who does the agent act as here?` },
          element: {
            type: 'static_select',
            action_id: 'identity',
            options: IDENTITY_OPTIONS,
            initial_option: initialIdentity,
          },
        });
      }
      blocks.push({
        type: 'input',
        optional: true,
        block_id: `tool:${p.provider}`,
        label: { type: 'plain_text', text: p.enabled ? `${p.provider}: available in this channel` : `${p.provider}: enable to configure` },
        element: {
          type: 'checkboxes',
          action_id: 'enabled',
          options: [enabledOption],
          ...(p.enabled ? { initial_options: [enabledOption] } : {}),
        },
      });
    }
  }

  // Carry the channel AND the OPEN-TIME governance state (compact keys: p/i/e) so the submit can tell a
  // deliberately-changed control from an untouched one that merely re-submits its initial value, the
  // basis for not reverting a concurrent member's change and not writing spurious rows. Non-secret.
  const open = (o.admin ?? []).map((p) => ({ p: p.provider, i: p.identity, e: p.enabled }));
  if (blocks.length > 100) throw new Error('Vouchr configuration exceeds the Slack modal block limit.');
  const privateMetadata = JSON.stringify({ channel: o.channel, open });
  if (privateMetadata.length > SLACK_VIEW_PRIVATE_METADATA_MAX) {
    throw new Error('Vouchr configuration exceeds the Slack modal private_metadata limit.');
  }
  return {
    type: 'modal',
    callback_id: CONFIG_CALLBACK,
    private_metadata: privateMetadata,
    title: { type: 'plain_text', text: 'Vouchr' },
    ...(o.admin && o.admin.length ? { submit: { type: 'plain_text', text: 'Save' } } : {}),
    close: { type: 'plain_text', text: 'Close' },
    blocks,
  };
}

/** THE readable line for one connection — the single escaped renderer for every surface that lists
 *  a connection (`/vouchr` status text, the config modal, the App Home rows). One renderer, one
 *  escape site (SEC-5): the provider id and the provider-reported account label must never hit
 *  mrkdwn raw anywhere. */
export function connectionLine(c: Connection): string {
  // Escape provider/account/channel before they hit mrkdwn: a stored provider id is attacker-
  // influenceable (see escapeMrkdwn's note) and the external account is provider-reported, so no value
  // here may render as a forged `<…|link>` or `<@user>` mention.
  const account = c.account ? ` (${escapeMrkdwn(c.account)})` : '';
  const where = c.channel ? `<#${escapeMrkdwn(c.channel)}>` : 'your DMs';
  return `• *${escapeMrkdwn(c.provider)}*${account} in ${where}`;
}

/** One connection row with its Disconnect button — the SAME row (and the same DISCONNECT_ACTION flow,
 *  including the native confirm) in the config modal and the App Home, so the revoke UX can't drift. */
function connectionRow(c: Connection): unknown {
  return {
    type: 'section',
    text: { type: 'mrkdwn', text: connectionLine(c) },
    accessory: {
      type: 'button',
      text: { type: 'plain_text', text: 'Disconnect', emoji: true },
      action_id: DISCONNECT_ACTION,
      // Internal Home/config builders supply the opaque row generation, binding a delayed click to
      // exactly what was rendered. Callers omitting it keep the historical serialized provider value
      // for compatibility, but Vouchr's built-in listener requires a server-resolved generation.
      value: c.credentialId ?? c.provider,
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
  };
}

/** DM shown after a user successfully connects a credential: what, where, and how to undo. */
export function connectedBlocks(
  provider: string,
  o: { channel: string | null; scope?: string; account?: string },
): unknown[] {
  // Escape like connectionLine (SEC-5): the account label comes from the provider's accountProbe
  // and the scope string from its token response — both provider-controlled; no value here may
  // render as a forged `<…|link>` or `<!channel>`.
  const p = escapeMrkdwn(provider);
  const where = o.channel ? `<#${escapeMrkdwn(o.channel)}>` : 'your DMs';
  const scope = o.scope ? ` (${escapeMrkdwn(o.scope)})` : '';
  const account = o.account ? `Connected as *${escapeMrkdwn(o.account)}*.\n` : '';
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:white_check_mark: *${p} connected*\n` +
          account +
          `Vouchr can now act as you on ${p} in ${where}${scope}. Your token is stored ` +
          `encrypted and is never shown to the agent or posted in Slack.`,
      },
    },
    contextBlock(`Disconnect any time with \`/vouchr disconnect ${p}\`.`),
  ];
}

/** One-line post-OAuth confirmation DM ("best-effort nudge back into Slack"). Same SEC-5 rule as
 *  connectionLine: the account label is provider-reported (accountProbe), so `<!channel>` or
 *  `<https://evil|click>` must render inert. One renderer, one escape site, testable. */
export function connectedDmText(provider: string, account: string | null): string {
  return `✅ ${escapeMrkdwn(provider)} connected${account ? ` as ${escapeMrkdwn(account)}` : ''}. Ask the agent again.`;
}

/** Message shown when a user declines consent (or consent is required and not granted). */
export function consentDeniedBlocks(provider: string, reason?: string): unknown[] {
  const p = escapeMrkdwn(provider);
  // Keep the optional parameter for source compatibility, but never render arbitrary caller text:
  // it may be a raw provider/OAuth error containing credential material. Stable copy is the only
  // safe contract; typed operational failures are normalized separately by mapSafeError.
  void reason;
  const why = `You haven't allowed ${p} for this request.`;
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:no_entry: *${p} not authorized*\n` +
          `${why} Nothing was sent on your behalf.`,
      },
    },
    contextBlock('Re-run the request to be prompted to connect again.'),
  ];
}

/** Fixed private recovery after an attributable OAuth callback failure. The closed core outcome and
 * recovery category select copy; provider-controlled query/error text is never accepted here. */
export function oauthRecoveryBlocks(
  provider: string,
  outcome: AttributedOAuthCallbackOutcome,
  recovery: VouchrRecovery,
): unknown[] {
  if (outcome === 'denied' && recovery !== 'contact_admin') return consentDeniedBlocks(provider);
  const p = escapeMrkdwn(provider);
  let detail: string;
  if (outcome === 'denied') {
    detail = 'Authorization was denied, but Vouchr could not record the outcome. Contact an administrator.';
  } else if (outcome === 'incomplete' && recovery === 'contact_admin') {
    detail = 'Authorization did not finish, and Vouchr could not record the outcome. Contact an administrator.';
  } else if (outcome === 'incomplete') {
    detail = 'Authorization did not finish, so no connection was saved. Ask the agent for a new private prompt.';
  } else if (outcome === 'state_expired') {
    detail = 'That connection request expired. Ask the agent for a new private prompt.';
  } else if (outcome === 'state_stale') {
    detail = 'That connection request is no longer current. Use the newest prompt, or ask the agent again.';
  } else if (outcome === 'setup_changed') {
    detail = recovery === 'contact_admin'
      ? 'Your account or connection setup changed before authorization finished. Contact an administrator before trying again.'
      : 'Connection setup changed before authorization finished. Ask the agent to resolve it again.';
  } else if (recovery === 'fix_configuration') {
    detail = 'The provider rejected Vouchr’s OAuth configuration. Ask an administrator to check it.';
  } else if (recovery === 'retry_later') {
    detail = 'The provider is temporarily unavailable. Wait, then ask the agent for a new private prompt.';
  } else if (recovery === 'connect') {
    detail = 'The provider rejected this connection attempt. Ask the agent for a new private prompt.';
  } else {
    detail = 'The connection could not be saved. Ask an administrator to check Vouchr before trying again.';
  }
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*${p} connection not completed*\n${detail}`,
      },
    },
  ];
}

/** `/vouchr status`: a user's current connections. */
export function statusBlocks(
  connections: Connection[],
  pagination?: { page: number; totalPages: number },
): unknown[] {
  if (connections.length === 0) {
    return [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: ':information_source: *No connections yet*\nConnections are created on demand — an agent prompts you to connect when it needs one.' },
      },
    ];
  }
  return [
    { type: 'header', text: { type: 'plain_text', text: 'Your Vouchr connections', emoji: true } },
    ...mrkdwnSections(connections.map(connectionLine), { maxSections: 48 }),
    contextBlock(pagination
      ? `Page ${pagination.page} of ${pagination.totalPages}. Browse with \`/vouchr status <page>\`. Disconnect with \`/vouchr disconnect <provider>\`.`
      : 'Disconnect with `/vouchr disconnect <provider>`.'),
  ];
}

/** Exported ephemeral confirm-prompt for host-owned surfaces. Its historical provider-valued button
 * remains unchanged; hosts own its listener and lifecycle semantics. Vouchr-owned Home/config rows
 * instead carry an opaque exact credential generation through {@link connectionRow}. */
export function disconnectConfirmBlocks(provider: string): unknown[] {
  const p = escapeMrkdwn(provider);
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:warning: *Disconnect ${p}?*\n` +
          `Vouchr will delete your stored ${p} credential. The agent won't be able to act as ` +
          `you on ${p} until you connect again.`,
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

export const HOME_CALLBACK = 'vouchr_home';
export const HOME_CHANNEL_ACTION = 'vouchr_home_channel';
export const HOME_IDENTITY_ACTION = 'vouchr_home_identity';
export const HOME_TOOL_ACTION = 'vouchr_home_tool';
export const HOME_CONFIGURE_ACTION = 'vouchr_home_configure';

/** Slack hard-caps a view at 100 blocks; cap each home list well under it and point the tail at
 *  `/vouchr` instead of paginating (#111 — a hard cap keeps the view build cheap and idempotent). */
const HOME_MAX_ROWS = 20;

/**
 * App Home tab (#111): the config console. Everyone sees their own connections — with the SAME
 * Disconnect row/flow as the config modal — plus the providers available to connect. `governance`
 * (passed only for viewers the adapter authorized server-side) adds the per-channel console: a
 * channel picker + one control row per provider (identity select, Enable/Disable, Configure). Its mere
 * presence is UX, never the security boundary — every block action re-checks membership at the mutation
 * (SEC-3). `note` replaces the control rows when the selected channel is ineligible/archived/deleted
 * or not this viewer's to configure. Omitting `governance` keeps the pre-#111 connections-only view.
 *
 * Returns UNSTAMPED view JSON (`{ type: 'home', blocks }`, exactly the pre-#111 shape): no
 * callback_id and no private_metadata, so a host reusing this exported helper for its OWN Home tab
 * is never mistaken for Vouchr's. Only Bolt's internal publisher stamps HOME_CALLBACK + the
 * selected-channel metadata (the App-Home "state machine") — that stamp is what the event and
 * disconnect handlers treat as ownership proof.
 */
export function homeView(o: {
  connections: Connection[];
  providers: string[];
  governance?: {
    channel: string | null;
    note?: string | null;
    tools?: ConfigMemberRow[];
  };
}): unknown {
  const connected = new Set(o.connections.map((c) => c.provider));
  const available = o.providers.filter((p) => !connected.has(p));
  const blocks: unknown[] = [
    { type: 'header', text: { type: 'plain_text', text: 'Vouchr', emoji: true } },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: o.connections.length
          ? '*Your connections*'
          : "*Your connections*\nNone yet — connect a provider below to let the agent act as you.",
      },
    },
  ];
  for (const c of o.connections.slice(0, HOME_MAX_ROWS)) blocks.push(connectionRow(c));
  if (o.connections.length > HOME_MAX_ROWS) {
    blocks.push(contextBlock(`+${o.connections.length - HOME_MAX_ROWS} more — browse them with \`/vouchr status\`.`));
  }
  if (available.length) {
    blocks.push({ type: 'divider' });
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: '*Available providers*\n' + available.slice(0, HOME_MAX_ROWS).map((p) => `• ${escapeMrkdwn(p)}`).join('\n') },
    });
    blocks.push(contextBlock('Connections are created on demand — ask the agent and you will be prompted to connect.'));
  }

  if (o.governance) {
    const g = o.governance;
    blocks.push({ type: 'divider' });
    blocks.push({ type: 'header', text: { type: 'plain_text', text: 'Channel governance', emoji: true } });
    blocks.push({
      type: 'actions',
      block_id: 'home_channel',
      elements: [
        {
          type: 'conversations_select',
          action_id: HOME_CHANNEL_ACTION,
          placeholder: { type: 'plain_text', text: 'Pick a channel to configure' },
          // Mirror the shared-channel safety rules at the picker: workspace channels only, no DMs, no
          // Slack Connect. UX filtering only — eligibility is re-checked server-side at render (the
          // core channelIneligibleReason rule) and again inside every mutation.
          filter: { include: ['public', 'private'], exclude_external_shared_channels: true, exclude_bot_users: true },
          ...(g.channel ? { initial_conversation: g.channel } : {}),
        },
      ],
    });
    if (!g.channel) {
      blocks.push(contextBlock('Pick a channel to see and configure which tools its members can use.'));
    } else if (g.note) {
      // g.note is Vouchr-authored constant text; the channel id came from an interaction payload,
      // so it is escaped at render (SEC-5).
      blocks.push(contextBlock(`<#${escapeMrkdwn(g.channel)}>: ${g.note}`));
    } else {
      const tools = g.tools ?? [];
      if (!tools.length) blocks.push(contextBlock('No providers are registered.'));
      for (const t of tools.slice(0, HOME_MAX_ROWS)) {
        // One row per REGISTERED provider (#111): brokered tools get the full set; a 'service' tool
        // keeps ONLY Enable/Disable (its allowlist bit is a valid channel control, while identity and
        // channel credentials are refused by core for it: no human credential to broker).
        const brokered = isBrokeredProvider(t);
        // Same options + initial contract as the config modal's identity select (STR-2).
        const initialIdentity = identityOption(t.identity);
        blocks.push({
          type: 'section',
          block_id: `home_identity:${t.provider}`,
          text: {
            type: 'mrkdwn',
            text: `*${escapeMrkdwn(t.provider)}*: ${t.enabled ? 'enabled' : 'disabled'} · ${
              brokered ? `acts as _${escapeMrkdwn(t.identity)}_` : '_service tool (host auth)_'
            }`,
          },
          ...(brokered && initialIdentity
            ? {
                accessory: {
                  type: 'static_select',
                  action_id: HOME_IDENTITY_ACTION,
                  options: IDENTITY_OPTIONS,
                  initial_option: initialIdentity,
                },
              }
            : {}),
        });
        blocks.push({
          type: 'actions',
          block_id: `home_tool:${t.provider}`,
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: t.enabled ? 'Disable' : 'Enable', emoji: true },
              action_id: HOME_TOOL_ACTION,
              // The TARGET state rides in the value (not a read-then-toggle), so a stale click can
              // never double-flip. Forgeable, like every interaction field — the handler re-validates
              // the provider (SEC-4) and re-checks membership (SEC-3) before anything is written.
              value: `${t.enabled ? 'disable' : 'enable'}:${t.provider}`,
              ...(t.enabled ? {} : { style: 'primary' }),
            },
            ...(brokered
              ? [{
                  type: 'button',
                  text: { type: 'plain_text', text: 'Connect shared account', emoji: true },
                  action_id: HOME_CONFIGURE_ACTION,
                  value: t.provider,
                }]
              : []),
          ],
        });
      }
      if (tools.length > HOME_MAX_ROWS) {
        blocks.push(contextBlock(`+${tools.length - HOME_MAX_ROWS} more — use \`/vouchr\` in the channel.`));
      }
    }
  }

  return { type: 'home', blocks };
}

