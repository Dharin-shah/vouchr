import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { ChannelConfig } from '../src/core/channelConfig';
import { defineProvider } from '../src/core/providers';
import { userOwner, channelOwner, type Owner } from '../src/core/owner';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, mintIdentity } from './support/identity';

// #51 owner-binding invariant — the cross-tenant guard in resolveOwner. This EXHAUSTIVELY enumerates
// the small tuple space (deterministic — better than random here) and asserts fail-closed behavior:
// the credential owner is chosen ONLY from the SIGNED claims, and the body handle's `owner` must merely
// MATCH the signed `ownerKind`. Observable: we wrap vault.get to record WHICH owner every credential
// read is keyed on. resolveOwner runs BEFORE the ConnectionHandle exists, so a refusal never queries the
// vault for a channel owner at all — "did any read reach a channel-owned credential" is the crux.

const KEY = randomBytes(32);
const SECRET = 'owner-binding-secret';
const TOKEN = 'tok_channel_secret_DO_NOT_LEAK';

const acme = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['api.acme.example'],
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

/** A broker with the channel gate wired iff `channelConfigSet`. Returns a recorder of every owner the
 *  vault is keyed on — the sole way to observe whether a channel credential was reached. */
async function makeBroker(t: TestContext, channelConfigSet: boolean) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  // Seed BOTH a user-owned (U1) and a channel-owned (C1) acme credential so a permitted resolution of
  // either actually returns a token (a happy path returns 200), while a refusal reaches neither.
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  await vault.upsert(channelOwner('T1', 'C1'), 'acme', {
    accessToken: TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });

  // Record every credential read's owner, then delegate to the real vault (keeps the injector contract).
  const reads: Owner[] = [];
  const realGet = vault.get.bind(vault);
  (vault as any).get = (owner: Owner, provider: string, onDecrypt?: () => void) => {
    reads.push(owner);
    return realGet(owner, provider, onDecrypt);
  };

  let channelConfig: ChannelConfig | undefined;
  if (channelConfigSet) {
    channelConfig = new ChannelConfig(db);
    await channelConfig.setMode('T1', 'C1', 'acme', 'shared'); // the channel owns one shared credential
  }

  const server = createBroker({ providers: [acme], vault, audit, db, identitySecret: identityConfig(SECRET), channelConfig });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  return { server, port, reads, reset: () => { reads.length = 0; } };
}

/** POST JSON to the broker over a real socket (global fetch is owned by the upstream mock). */
function post(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try { json = JSON.parse(raw); } catch { /* leave null */ }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(data);
  });
}

const BODY_OWNERS = ['user', 'channel'] as const;
const SIGNED_KINDS = ['user', 'channel', undefined] as const;

test('#51 owner-binding: exhaustive enumeration — a channel credential is reached ONLY on a fully-signed match, else fail-closed', async (t) => {
  // Mock the upstream provider fetch so a permitted resolution returns 200 rather than hitting the wire.
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;

  const brokers = { true: await makeBroker(t, true), false: await makeBroker(t, false) };
  try {
    let i = 0; // loop index doubles as the deterministic seed — no wall-clock dependence anywhere.
    for (const channelConfigSet of [true, false] as const) {
      const b = brokers[`${channelConfigSet}` as 'true' | 'false'];
      for (const bodyOwner of BODY_OWNERS) {
        for (const signedKind of SIGNED_KINDS) {
          for (const eligible of [true, false] as const) {
            i++;
            b.reset();
            // The enumeration ORDER is fully deterministic; the only nondeterminism is mintIdentity's
            // fresh random jti (a single-use nonce, required so no two calls collide as replays). We do
            // NOT derive any test decision from a clock — `i` is used only to prove grid coverage below.
            const token = mintIdentity(
              {
                teamId: 'T1', userId: 'U1', channel: 'C1',
                ...(signedKind !== undefined ? { ownerKind: signedKind } : {}),
                channelEligible: eligible,
              },
              SECRET,
            );
            const r = await post(b.port, '/v1/fetch', {
              handle: { provider: 'acme', owner: bodyOwner }, identityToken: token, method: 'GET', path: '/x',
            });

            const effectiveKind = signedKind ?? 'user'; // an ABSENT signed claim defaults to 'user'
            const reachedChannel = b.reads.some((o) => o.kind === 'channel');

            // (a) A channel credential is reachable ONLY when body owner === signed ownerKind === 'channel'
            //     AND channelConfig is set AND the signed eligibility verdict holds. Every other tuple is
            //     fail-closed: the channel credential is NEVER read.
            const shouldReachChannel = bodyOwner === 'channel' && signedKind === 'channel' && channelConfigSet && eligible;
            const label = `body=${bodyOwner} signed=${String(signedKind)} cc=${channelConfigSet} elig=${eligible}`;
            assert.equal(reachedChannel, shouldReachChannel, `channel-credential reachability wrong for ${label}`);

            if (shouldReachChannel) {
              // Happy path: injected the CHANNEL-owned credential, keyed on the channel, never the caller.
              assert.equal(r.status, 200, `expected 200 on the permitted channel path for ${label}`);
              assert.ok(
                b.reads.some((o) => o.kind === 'channel' && o.id === 'C1' && o.teamId === 'T1'),
                `channel read must be keyed on channelOwner(T1,C1) for ${label}`,
              );
            } else if (bodyOwner !== effectiveKind) {
              // (b) The body handle's owner must MATCH the signed ownerKind. A forged body owner:'channel'
              //     on a 'user'/absent claim — and the reverse — is refused 403 before any vault read.
              //     Deleting resolveOwner's match check flips this: the (user, signed:channel) tuple stops
              //     returning 403 (it would fall through to the channel branch), so this assertion fails.
              assert.equal(r.status, 403, `owner mismatch must be 403 for ${label}`);
              assert.equal(reachedChannel, false, `a refused mismatch must not read a channel cred for ${label}`);
            } else if (bodyOwner === 'channel' && signedKind === 'channel') {
              // A fully-matched channel request that is STILL refused: channelConfig unset OR the signed
              //     eligibility verdict is false/absent. Assert the request is refused OUTRIGHT (403), not
              //     just that no channel cred was read — a regression that DOWNGRADED to serving the
              //     caller's own USER credential would also read no channel owner and slip past that alone.
              assert.equal(r.status, 403, `matched channel but ineligible/disabled must be refused 403 for ${label}`);
            }
          }
        }
      }
    }
    // Sanity: we walked the whole 2 (cc) * 2 (bodyOwner) * 3 (signedKind) * 2 (eligible) grid, so the one
    // permitted channel tuple is actually exercised (shouldReachChannel isn't vacuously false everywhere).
    assert.equal(i, 24, 'exhaustive grid must be 2*2*3*2 = 24 cases');
  } finally {
    globalThis.fetch = realFetch;
    brokers.true.server.close();
    brokers.false.server.close();
  }
});

test('#51 owner-binding: a forged body owner:"channel" on a plain user token never reaches a channel credential (fail-closed)', async (t) => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  const b = await makeBroker(t, true); // gate ENABLED — the refusal is the signed-mismatch, not a missing config
  try {
    // Plain user token (no signed ownerKind) + a forged body owner:'channel'. Refused 403; the channel
    // credential is never read — a forged body alone can never cross into a channel-owned credential.
    const token = mintIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1', channelEligible: true }, SECRET);
    const r = await post(b.port, '/v1/fetch', { handle: { provider: 'acme', owner: 'channel' }, identityToken: token, method: 'GET', path: '/x' });
    assert.equal(r.status, 403);
    assert.equal(b.reads.some((o) => o.kind === 'channel'), false, 'forged channel handle must not read a channel cred');
  } finally {
    globalThis.fetch = realFetch;
    b.server.close();
  }
});

test('#51 owner-binding: the resolved credential owner derives ONLY from signed claims, never the body', async (t) => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as any;
  const b = await makeBroker(t, false);
  try {
    // The signed acting human is U1 in T1. The body tries to imply a DIFFERENT owner (U2 / T2 / C9).
    // The vault must be keyed on the claims-derived owner (userOwner(T1,U1)) — never the body's values.
    const token = mintIdentity({ teamId: 'T1', userId: 'U1', channel: 'C1' }, SECRET);
    const r = await post(b.port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: token, method: 'GET', path: '/x',
      // body-level identity that MUST be ignored:
      teamId: 'T2', userId: 'U2', channel: 'C9', ownerKind: 'channel', owner: { id: 'U2' },
    } as any);
    assert.equal(r.status, 200, 'the claims owner (U1) has a seeded credential');
    assert.ok(b.reads.length > 0, 'the vault was read');
    for (const o of b.reads) {
      assert.equal(o.kind, 'user', 'owner kind derives from the signed claim (user), not the body');
      assert.equal(o.id, 'U1', 'owner id derives from the signed userId, never the body-supplied U2');
      assert.equal(o.teamId, 'T1', 'owner team derives from the signed teamId, never the body-supplied T2');
    }
  } finally {
    globalThis.fetch = realFetch;
    b.server.close();
  }
});
