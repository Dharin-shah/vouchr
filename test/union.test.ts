import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../src/core/db';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Consent } from '../src/core/consent';
import { ChannelConfig } from '../src/core/channelConfig';
import { ChannelTools } from '../src/core/tools';
import { Policy } from '../src/core/policy';
import { ProviderRegistry, defineProvider } from '../src/core/providers';
import { userOwner } from '../src/core/owner';
import { ConnectContext } from '../src/adapters/bolt';
import { ConsentRequiredError } from '../src/adapters/bolt';

const KEY = randomBytes(32);
const CALLER = { enterpriseId: null, teamId: 'T1', userId: 'U_CALLER' }; // triggers the request
const ALICE = { enterpriseId: null, teamId: 'T1', userId: 'U_ALICE' };   // the connected member
const tok = (account: string) => ({ accessToken: 'sk-alice-secret', refreshToken: null, scopes: '', expiresAt: null, externalAccount: account });

// A normal human-brokered provider (acting_human is the default).
const mcp = defineProvider({
  id: 'mcp', authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false, clientId: 'c', clientSecret: 's',
});
// A service-to-service tool Vouchr must NOT broker.
const svc = defineProvider({
  id: 'svc', identity: 'service', credential: 'key',
  authorizeUrl: 'https://x/a', tokenUrl: 'https://x/t', scopesDefault: [],
  egressAllow: ['api.test'], refresh: 'none', pkce: false,
});

function build(channel: string | null = 'C_FIN', members: string[] = ['U_CALLER', 'U_ALICE']) {
  const posted: any[] = [];
  const client = {
    users: { info: async () => ({ user: { is_admin: true } }) },
    conversations: {
      info: async () => ({ channel: { id: 'C_FIN', is_channel: true } }),
      members: async () => ({ members }),
    },
    chat: { postEphemeral: async (a: any) => { posted.push(a); }, postMessage: async (a: any) => { posted.push(a); } },
  } as any;
  return { client, posted };
}

async function ctx(channel: string | null = 'C_FIN', members: string[] = ['U_CALLER', 'U_ALICE']) {
  const db = await openDb({ dbPath: ':memory:' });
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  const { client, posted } = build(channel, members);
  const c = new ConnectContext(
    CALLER, channel, client, new ProviderRegistry([mcp, svc]), vault, audit,
    new Consent(db), new Policy(), 'http://x', {}, new ChannelConfig(db), new ChannelTools(db),
    new Map(), () => {}, ['mcp', 'svc'],
  );
  return { c, db, vault, audit, posted, cfg: new ChannelConfig(db) };
}

const injectRow = (db: any) =>
  db.get(`SELECT user_id, channel, meta FROM audit WHERE action='inject' ORDER BY at DESC LIMIT 1`);

// Acceptance: union resolves to a connected member and audits THAT member as the actor — never the
// caller and never the channel (no owner/actor conflation).
test('union resolves to a connected member and audits that member (not caller, not channel)', async () => {
  const { c, db, vault } = await ctx();
  await new ChannelConfig(db).setMode('T1', 'C_FIN', 'mcp', 'union');
  await vault.upsert(userOwner(ALICE), 'mcp', tok('alice@example.com')); // only Alice is connected

  const handle = await c.connect('mcp');
  // The credential is Alice's user-owned cred (owner key = the member, never the channel).
  assert.equal(await handle.account(), 'alice@example.com');

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('ok', { status: 200 })) as any;
  try {
    await handle.fetch('https://api.test/x');
  } finally {
    globalThis.fetch = realFetch;
  }

  const row = await injectRow(db);
  assert.equal(row.user_id, 'U_ALICE');   // audited AS the connected member (the acting actor)
  assert.notEqual(row.user_id, 'U_CALLER'); // NOT the caller who triggered it
  assert.equal(row.channel, null);          // user-owned → not attributed to the channel (no conflation)
  assert.ok(!row.meta.includes('sk-alice-secret')); // and the secret never reaches the audit log
});

// union with NO connected member falls through to prompting the caller (so they become a member).
test('union with no connected member prompts the caller for consent', async () => {
  const { c, posted } = await ctx('C_FIN', ['U_CALLER']); // caller present, nobody connected
  await (c as any).channelConfig.setMode('T1', 'C_FIN', 'mcp', 'union');
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError);
  assert.equal(posted.length, 1); // a Connect prompt was posted to the caller
});

// A 'service' tool is OUT of Vouchr's scope: connect() refuses it with NO consent flow at all.
test('service identity: connect refuses without any consent prompt', async () => {
  const { c, db, posted } = await ctx();
  await assert.rejects(() => c.connect('svc'), /service-to-service/);
  assert.equal(posted.length, 0); // no Connect prompt posted
  const consentRows = (await db.all('SELECT 1 FROM consent_request')) as any[];
  assert.equal(consentRows.length, 0); // and no consent round-trip was started
});

// Contrast: an acting_human tool with no stored cred DOES route through the consent flow.
test('acting_human identity: connect routes through consent', async () => {
  const { c, db, posted } = await ctx();
  await assert.rejects(() => c.connect('mcp'), ConsentRequiredError);
  assert.equal(posted.length, 1); // a Connect prompt was posted
  const consentRows = (await db.all('SELECT 1 FROM consent_request')) as any[];
  assert.equal(consentRows.length, 1); // a consent state was created
});

// The manifest surfaces identity so a host can see which tools Vouchr brokers vs. which it cedes.
test('toolManifest reports identity per provider', async () => {
  const { c } = await ctx();
  const m = await c.toolManifest();
  assert.deepEqual(
    m.map((e) => [e.provider, e.identity]),
    [['mcp', 'acting_human'], ['svc', 'service']],
  );
});
