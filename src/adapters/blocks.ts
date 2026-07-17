import type { AuditRow, StatsRow } from '../core/audit';
import { CHANNEL_MODES, isChannelMode } from '../core/channelConfig';
import { isBrokeredProvider } from '../core/providers';
import { SECRET_REFERENCE_SOURCES, type SecretReferenceSource } from '../core/reference';

/** Escape the three chars Slack mrkdwn treats specially, so a value that reached the audit table can
 *  never render as a link/mention/broadcast. The `provider` column is attacker-controllable (e.g. an
 *  unvalidated `/vouchr configure <arg>` denial writes `arg` there), so an admin's `audit channel`
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
          `encrypted on this server and is never shown to the agent or posted in Slack.`,
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
 * binds to the right owner (a channel for admin config, or nothing for a per-user key).
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

/** Admin modal: set the CHANNEL's shared credential (invariant 7, admin-gated upstream). */
export function configureModal(
  provider: string,
  channel: string,
  referenceSources: readonly SecretReferenceSource[] = SECRET_REFERENCE_SOURCES,
  requestId?: string,
): unknown {
  const p = escapeMrkdwn(provider);
  return secretModal({
    callbackId: CONFIGURE_CALLBACK,
    // Built-in Slack flows carry only the opaque request id. Preserve the legacy metadata shape
    // when hosts call this exported renderer directly without the request-backed dispatcher.
    meta: requestId === undefined ? { channel, provider } : { requestId },
    title: 'Channel credential',
    referenceSources,
    intro:
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
          value: requestId,
          style: 'primary',
        },
      ],
    },
  ];
}

/** Ephemeral in-thread prompt. The button carries only an opaque pending-request id; provider,
 *  identity, channel, and thread are reloaded and revalidated at the mutation. */
export function sessionApprovalBlocks(provider: string, requestId: string): unknown[] {
  const p = escapeMrkdwn(provider);
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          `:lock: *Allow ${p} in this thread?*\n` +
          `The agent will be able to act as you on ${p} only inside this thread, until the ` +
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
          value: requestId,
          style: 'primary',
        },
      ],
    },
  ];
}

export const APPROVAL_APPROVE_ACTION = 'vouchr_approval_approve';
export const APPROVAL_DENY_ACTION = 'vouchr_approval_deny';

/**
 * Approve/Deny prompt for ONE sensitive write (#113), the per-action sibling of
 * sessionApprovalBlocks. Shows provider, method, host, a bounded salted action fingerprint and — for a
 * query-bearing request —
 * only the COUNT of query parameters (GHSA-pg84). Parameter names and values are BOTH
 * caller-controlled and can carry tokens, signed-URL material, or PII, so neither is ever
 * rendered (SEC-1); the copy tells the human the exact query is bound byte-for-byte. The request
 * body is likewise never shown. The buttons carry ONLY the pending-approval id: content or
 * authority in a button value would be forgeable (SEC-3) — the click handler re-validates the
 * provider against the registry and re-checks approver eligibility server-side. Every
 * interpolated value is escaped at render (SEC-5); `requester` is an authenticated Slack user id,
 * rendered as a mention.
 */
export function approvalBlocks(o: {
  provider: string;
  method: string;
  host: string;
  actionFingerprint: string;
  /** How many query parameters the request carries (0 = none). Names/values are never shown. */
  queryParamCount: number;
  requester: string;
  id: string;
  approver: 'self' | 'admin';
}): unknown[] {
  const p = escapeMrkdwn(o.provider);
  const n = o.queryParamCount;
  const query = n ? `?… (${n} parameter${n === 1 ? '' : 's'})` : '';
  // Raw paths are never rendered: they are caller-controlled and can embed tokens, signed webhook
  // material, or PII. The fixed-size fingerprint is the same value recorded in audit, while the
  // short-lived internal row retains the raw bytes solely for exact grant matching.
  const action = `${o.method} ${o.host}\nAction fingerprint: ${o.actionFingerprint}`;
  const bound = n
    ? ' The exact query string is bound byte-for-byte (its parameters are not displayed); any change re-prompts.'
    : '';
  const intro = o.approver === 'admin'
    ? `The agent wants to run an action on ${p} for <@${escapeMrkdwn(o.requester)}>. An admin must approve it.`
    : `The agent wants to run an action as you on ${p}.`;
  return [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `:lock: *Approve this ${p} action?*\n${intro}`,
      },
    },
    {
      type: 'section',
      text: { type: 'plain_text', text: action, emoji: false },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `${query ? `${query}. ` : ''}The fingerprint binds the exact owner, method, endpoint, and query string — once — and expires if unused.${bound} The raw path and request body are not displayed or inspected.`,
      },
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: 'Approve', emoji: true },
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

/** The four per-channel auth modes, in the order the config modal lists them. */
/** One connection row for the status / home views. `channel` null = a personal (DM) credential.
 *  `account` is the provider-reported external account (escaped at render — provider-influenced).
 *  Vouchr-owned interactive views add the opaque `credentialId`; keeping it optional preserves the
 *  existing exported renderer input shape, while the built-in action handler refuses that fallback. */
export type Connection = {
  provider: string;
  channel: string | null;
  mode?: string;
  account?: string | null;
  credentialId?: string;
};

/** One provider's read-only channel tool state, for the config modal's "Tools in this channel" list. */
export type ToolRow = { provider: string; enabled: boolean; mode?: string | null };

/** One provider's admin control row: channel mode (null = unconfigured) + tool-enabled. */
export type ConfigAdminRow = {
  provider: string;
  mode: string | null;
  enabled: boolean;
  /** Manifest identity (see ToolManifestEntry). 'service' rows get only the tool Enable/Disable
   *  control — mode/credential mutations are refused by core for them. Absent = 'acting_human'. */
  identity?: 'service' | 'acting_human';
};

const CONFIG_CONNECTION_ROWS_MAX = 10;

/**
 * No-arg `/vouchr` config modal (#109). Three sections:
 *  - "Your connections" (EVERYONE): a bounded first set with Disconnect buttons, plus explicit
 *    `/vouchr status [page]` guidance when more rows exist.
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
    for (const c of o.connections.slice(0, CONFIG_CONNECTION_ROWS_MAX)) blocks.push(connectionRow(c));
    if (o.connections.length > CONFIG_CONNECTION_ROWS_MAX) {
      blocks.push({
        type: 'context',
        elements: [{
          type: 'mrkdwn',
          text: `+${o.connections.length - CONFIG_CONNECTION_ROWS_MAX} more — use \`/vouchr status\` to browse every connection, then \`/vouchr disconnect <provider>\`.`,
        }],
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
    blocks.push(...mrkdwnSections(o.tools.map((t) => `• *${escapeMrkdwn(t.provider)}*: ${t.enabled ? 'enabled' : 'disabled'}${t.mode ? ` (${escapeMrkdwn(t.mode)})` : ''}`), { maxSections: 96 }));
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
    }
  }

  // Carry the channel AND the OPEN-TIME admin state (compact keys: p/m/e) so the submit can tell a
  // deliberately-changed control from an untouched one that merely re-submits its initial value — the
  // basis for not reverting a concurrent admin's change and not writing spurious rows. Non-secret.
  const open = (o.admin ?? []).map((p) => ({ p: p.provider, m: p.mode, e: p.enabled }));
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
  // Escape provider/account/channel/mode before they hit mrkdwn: a stored provider id is attacker-
  // influenceable (see escapeMrkdwn's note) and the external account is provider-reported, so no value
  // here may render as a forged `<…|link>` or `<@user>` mention.
  const account = c.account ? ` (${escapeMrkdwn(c.account)})` : '';
  const where = c.channel ? `<#${escapeMrkdwn(c.channel)}>` : 'your DMs';
  const mode = c.mode ? ` — _${escapeMrkdwn(c.mode)}_` : '';
  return `• *${escapeMrkdwn(c.provider)}*${account} in ${where}${mode}`;
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
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `Disconnect any time with \`/vouchr disconnect ${p}\`.` }],
    },
  ];
}

/** One-line post-OAuth confirmation DM ("best-effort nudge back into Slack"). Same SEC-5 rule as
 *  connectionLine: the account label is provider-reported (accountProbe), so `<!channel>` or
 *  `<https://evil|click>` must render inert. One renderer, one escape site, testable. */
export function connectedDmText(provider: string, account: string | null): string {
  return `✅ ${escapeMrkdwn(provider)} connected${account ? ` as ${escapeMrkdwn(account)}` : ''}.`;
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
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: 'Re-run the request to be prompted to connect again.' }],
    },
  ];
}

/** `/vouchr status`: a user's current connections and per-channel modes. */
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
    {
      type: 'context',
      elements: [{
        type: 'mrkdwn',
        text: pagination
          ? `Page ${pagination.page} of ${pagination.totalPages}. Browse with \`/vouchr status <page>\`. Disconnect with \`/vouchr disconnect <provider>\`.`
          : 'Disconnect with `/vouchr disconnect <provider>`.',
      }],
    },
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
export const HOME_MODE_ACTION = 'vouchr_home_mode';
export const HOME_TOOL_ACTION = 'vouchr_home_tool';
export const HOME_CONFIGURE_ACTION = 'vouchr_home_configure';

/** Slack hard-caps a view at 100 blocks; cap each home list well under it and point the tail at
 *  `/vouchr` instead of paginating (#111 — a hard cap keeps the view build cheap and idempotent). */
const HOME_MAX_ROWS = 20;

/**
 * App Home tab (#111): the config console. Everyone sees their own connections — with the SAME
 * Disconnect row/flow as the config modal — plus the providers available to connect. `governance`
 * (passed only for viewers the adapter authorized server-side) adds the per-channel console: a
 * channel picker + one control row per provider (mode select, Enable/Disable, Configure). Its mere
 * presence is UX, never the security boundary — every block action re-checks admin at the mutation
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
    tools?: ConfigAdminRow[];
  };
}): unknown {
  const note = (text: string): unknown => ({ type: 'context', elements: [{ type: 'mrkdwn', text }] });
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
    blocks.push(note(`+${o.connections.length - HOME_MAX_ROWS} more — browse them with \`/vouchr status\`.`));
  }
  if (available.length) {
    blocks.push({ type: 'divider' });
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: '*Available providers*\n' + available.slice(0, HOME_MAX_ROWS).map((p) => `• ${escapeMrkdwn(p)}`).join('\n') },
    });
    blocks.push(note('Connections are created on demand — ask the agent and you will be prompted to connect.'));
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
      blocks.push(note('Pick a channel to see and configure which tools its members can use.'));
    } else if (g.note) {
      // g.note is Vouchr-authored constant text; the channel id came from an interaction payload,
      // so it is escaped at render (SEC-5).
      blocks.push(note(`<#${escapeMrkdwn(g.channel)}>: ${g.note}`));
    } else {
      const tools = g.tools ?? [];
      if (!tools.length) blocks.push(note('No providers are registered.'));
      for (const t of tools.slice(0, HOME_MAX_ROWS)) {
        // One row per REGISTERED provider (#111): brokered tools get the full set; a 'service' tool
        // keeps ONLY Enable/Disable — its allowlist bit is a valid channel control, while mode and
        // channel credentials are refused by core for it (no human credential to broker).
        const brokered = isBrokeredProvider(t);
        // Same options + initial contract as the config modal's mode select: the modes list is the
        // core-exported CHANNEL_MODES (STR-2), initial only when a mode is actually configured.
        const modeOptions = CHANNEL_MODES.map((m) => ({ text: { type: 'plain_text', text: m }, value: m }));
        const initialMode = isChannelMode(t.mode) ? modeOptions.find((x) => x.value === t.mode) : undefined;
        blocks.push({
          type: 'section',
          block_id: `home_mode:${t.provider}`,
          text: {
            type: 'mrkdwn',
            text: `*${escapeMrkdwn(t.provider)}* — ${t.enabled ? 'enabled' : 'disabled'} · ${
              brokered ? `_${escapeMrkdwn(t.mode ?? 'per-user')}_` : '_service tool (host auth)_'
            }`,
          },
          ...(brokered
            ? {
                accessory: {
                  type: 'static_select',
                  action_id: HOME_MODE_ACTION,
                  placeholder: { type: 'plain_text', text: 'per-user (default)' },
                  options: modeOptions,
                  ...(initialMode ? { initial_option: initialMode } : {}),
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
              // the provider (SEC-4) and re-checks admin (SEC-3) before anything is written.
              value: `${t.enabled ? 'disable' : 'enable'}:${t.provider}`,
              ...(t.enabled ? {} : { style: 'primary' }),
            },
            ...(brokered
              ? [{
                  type: 'button',
                  text: { type: 'plain_text', text: 'Configure credential', emoji: true },
                  action_id: HOME_CONFIGURE_ACTION,
                  value: t.provider,
                }]
              : []),
          ],
        });
      }
      if (tools.length > HOME_MAX_ROWS) {
        blocks.push(note(`+${tools.length - HOME_MAX_ROWS} more — use \`/vouchr\` in the channel.`));
      }
    }
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
