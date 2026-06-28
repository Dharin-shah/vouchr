/** Block Kit for the in-Slack "connect your account" prompt (ephemeral). */
export function connectBlocks(provider: string, authorizeUrl: string): unknown[] {
  return [
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
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: `Connect ${provider}`, emoji: true },
          url: authorizeUrl,
          style: 'primary',
        },
      ],
    },
  ];
}

export const CONFIGURE_CALLBACK = 'vouchr_configure';
export const USER_KEY_CALLBACK = 'vouchr_user_key';
export const SETUP_KEY_ACTION = 'vouchr_setup_key';

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

/** Confirmation HTML shown in the browser tab after a successful connect. */
export function connectedHtml(provider: string, account: string | null): string {
  const who = account ? ` as ${account}` : '';
  return `<!doctype html><html><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
    <h2>✅ ${provider} connected${who}</h2>
    <p>You can close this tab and return to Slack.</p>
  </body></html>`;
}
