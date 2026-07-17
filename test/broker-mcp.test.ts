import { test, type TestContext } from 'node:test';
import { openTestDb } from './support/pg';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Vault } from '../src/core/vault';
import { Audit } from '../src/core/audit';
import { Policy } from '../src/core/policy';
import { ChannelTools, setChannelToolEnabled } from '../src/core/tools';
import { ChannelConfig, writeChannelMode } from '../src/core/channelConfig';
import { Consent } from '../src/core/consent';
import type { Db } from '../src/core/db';
import { defineProvider, type Provider } from '../src/core/providers';
import { channelOwner, userOwner } from '../src/core/owner';
import { createBroker } from '../src/adapters/http/broker';
import { identityConfig, signIdentity, type IdentityClaims } from './support/identity';

// ─────────────────────────────────────────────────────────────────────────────
// #65 POST /v1/mcp — MCP-aware egress proxy: SSE + session-header passthrough, stateless.
//
// Everything here drives the broker's real HTTP surface against a mocked upstream (global fetch),
// fully offline (TEST-2). The invariants under test: identity from the signed token only; every
// /v1/fetch gate (egress host, replay, policy, write opt-ins) applies BEFORE any byte flows; the
// credential is injected inside the broker and appears NOWHERE the caller can see; SSE streams
// through incrementally; Mcp-Session-Id / MCP-Protocol-Version round-trip; the stream ceilings
// terminate (never a clean end); and the broker holds no MCP session state.
// ─────────────────────────────────────────────────────────────────────────────

const KEY = randomBytes(32);
const SECRET = 'broker-signing-secret';
const SECRET_TOKEN = 'tok_super_secret_value_DO_NOT_LEAK'; // the vaulted token that must never escape

// An MCP-serving provider: POST is how JSON-RPC rides Streamable HTTP (so the provider opts into
// it), and the /v1/mcp route itself is a second, declarative opt-in via the `mcp` knob.
const mcpAcme = defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/auth',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['x'],
  egressAllow: ['mcp.acme.example'],
  egressMethods: ['POST'],
  mcp: { paths: ['/mcp'] },
  refresh: 'none',
  pkce: false,
  clientId: 'id',
  clientSecret: 'sec',
});

function claims(over: Partial<IdentityClaims> = {}): IdentityClaims {
  return { teamId: 'T1', userId: 'U1', channel: 'C1', exp: Date.now() + 60_000, jti: randomUUID(), ...over };
}

/** One /v1/mcp envelope with a fresh single-use identity token (mint per JSON-RPC call). */
function envelope(over: Record<string, unknown> = {}) {
  return {
    handle: { provider: 'acme', owner: 'user' },
    identityToken: signIdentity(claims(), SECRET),
    path: '/mcp',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
    ...over,
  };
}

/** The equivalent /v1/fetch POST envelope, used to prove both broker egress doors expose the same
 * typed recovery metadata without matching their legacy `error` prose. */
function fetchEnvelope(over: Record<string, unknown> = {}) {
  return {
    handle: { provider: 'acme', owner: 'user' },
    identityToken: signIdentity(claims(), SECRET),
    method: 'POST',
    path: '/mcp',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
    ...over,
  };
}

function recoveryFields(raw: string): Record<string, unknown> {
  const value = JSON.parse(raw);
  return {
    code: value.code,
    retryable: value.retryable,
    recovery: value.recovery,
    ...(value.retryAfterMs === undefined ? {} : { retryAfterMs: value.retryAfterMs }),
  };
}

/** Broker with U1's acme credential seeded and the write path opted in (MCP rides POST). */
type BrokerExtra = Partial<Parameters<typeof createBroker>[0]>;

async function makeMcpBroker(
  t: TestContext,
  extra: BrokerExtra | ((db: Db) => BrokerExtra | Promise<BrokerExtra>) = {},
) {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const resolvedExtra = typeof extra === 'function' ? await extra(db) : extra;
  const server = createBroker({ providers: [mcpAcme], vault, audit, db, identitySecret: identityConfig(SECRET), allowWrites: true, ...resolvedExtra });
  await new Promise<void>((r) => server.listen(0, r));
  return { server, vault, db, port: (server.address() as any).port };
}

/** Mock the upstream MCP server (global fetch). Records url/method/auth/headers/body/signal. */
function mockUpstream(respond: (url: string, init: any) => Response | Promise<Response>) {
  const real = globalThis.fetch;
  const seen: { url: string; method: string; auth: string | null; headers: Headers; body: unknown; signal: AbortSignal | undefined }[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    const headers = new Headers(init?.headers);
    seen.push({ url: String(url), method: init?.method ?? 'GET', auth: headers.get('authorization'), headers, body: init?.body, signal: init?.signal });
    return respond(String(url), init);
  }) as any;
  return { seen, restore: () => { globalThis.fetch = real; } };
}

/**
 * POST an envelope to a broker route over a real socket and capture the RAW streamed response:
 * status, headers, chunks as they arrive (`onChunk`), and whether the stream ended cleanly
 * (`clean:false` = the broker tore the socket down — the ceiling/termination signal).
 */
function postRaw(
  port: number,
  path: string,
  body: unknown,
  onChunk?: (sofar: string) => void,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; raw: string; clean: boolean }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    let sawResponse = false;
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'POST',
        // Node 22's global Agent keeps sockets alive. Each test below owns a short-lived server on
        // an ephemeral port, so pooling can attach a later request to a stale socket after port
        // reuse under full-suite load. A dedicated socket keeps this transport test deterministic.
        agent: false,
        headers: { 'content-type': 'application/json', 'content-length': data.length },
      },
      (res) => {
        sawResponse = true;
        const chunks: Buffer[] = [];
        let ended = false;
        res.on('data', (c: Buffer) => { chunks.push(c); onChunk?.(Buffer.concat(chunks).toString('utf8')); });
        res.on('end', () => { ended = true; });
        res.on('error', () => undefined); // a torn-down stream surfaces via 'close' below
        res.on('close', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, raw: Buffer.concat(chunks).toString('utf8'), clean: ended }));
      },
    );
    req.on('error', (e) => { if (!sawResponse) reject(e); }); // post-response resets resolve via 'close'
    req.end(data);
  });
}

const sse = (data: string) => `data: ${data}\n\n`;

// ── the acceptance flow: initialize → tools/list → tools/call, credential injected, never revealed ──

test('#65 mcp: initialize/listTools/callTool round trip — token injected, session + protocol headers pass both ways, secret never revealed', async (t) => {
  const { server, port, db } = await makeMcpBroker(t);
  const up = mockUpstream((_url, init) => {
    const rpc = JSON.parse(String(init.body));
    if (rpc.method === 'initialize') {
      // The MCP server ISSUES the session id + protocol version on initialize.
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { capabilities: {} } }), {
        status: 200,
        headers: { 'content-type': 'application/json', 'mcp-session-id': 'sess-123', 'mcp-protocol-version': '2025-03-26' },
      });
    }
    if (rpc.method === 'tools/list') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { tools: [{ name: 'echo' }] } }), {
        status: 200, headers: { 'content-type': 'application/json', 'mcp-session-id': 'sess-123' },
      });
    }
    // tools/call answers over SSE (Streamable HTTP lets the server pick the stream form).
    return new Response(sse(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: 'done' }] } })), {
      status: 200, headers: { 'content-type': 'text/event-stream', 'mcp-session-id': 'sess-123' },
    });
  });
  try {
    // 1) initialize — no session yet; caller junk headers (incl. Authorization) must be stripped.
    const init = await postRaw(port, '/v1/mcp', envelope({
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      headers: {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        'mcp-protocol-version': '2025-03-26',
        authorization: 'Bearer attacker-token',
        'x-evil': 'nope',
      },
    }));
    assert.equal(init.status, 200);
    assert.equal(init.clean, true);
    assert.equal(init.headers['mcp-session-id'], 'sess-123', 'session id issued upstream reaches the caller');
    assert.equal(init.headers['mcp-protocol-version'], '2025-03-26', 'protocol version passes provider→caller');
    assert.equal(up.seen[0].auth, `Bearer ${SECRET_TOKEN}`, 'the broker injected the vaulted credential');
    assert.equal(up.seen[0].headers.get('accept'), 'application/json, text/event-stream', 'Accept forwarded (Streamable HTTP requires it)');
    assert.equal(up.seen[0].headers.get('mcp-protocol-version'), '2025-03-26', 'protocol version passes caller→provider');
    assert.equal(up.seen[0].headers.get('x-evil'), null, 'non-allowlisted headers are stripped');

    // 2) tools/list — the HOST threads the session id back; the broker passes it through, stateless.
    const list = await postRaw(port, '/v1/mcp', envelope({
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'mcp-session-id': 'sess-123' },
    }));
    assert.equal(list.status, 200);
    assert.ok(list.raw.includes('"echo"'), 'tools/list result relayed verbatim');
    assert.equal(up.seen[1].headers.get('mcp-session-id'), 'sess-123', 'session id passes caller→provider');

    // 3) tools/call — the result arrives as SSE and relays with its content-type intact.
    const call = await postRaw(port, '/v1/mcp', envelope({
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo' } }),
      headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'mcp-session-id': 'sess-123' },
    }));
    assert.equal(call.status, 200);
    assert.match(call.headers['content-type'] ?? '', /^text\/event-stream/);
    assert.ok(call.raw.includes('"done"'), 'SSE callTool result relayed');

    // SEC-1: the vaulted token appears NOWHERE the caller can see — bodies, headers, any call.
    for (const r of [init, list, call]) {
      assert.ok(!r.raw.includes(SECRET_TOKEN), 'secret must not appear in a relayed body');
      assert.ok(!JSON.stringify(r.headers).includes(SECRET_TOKEN), 'secret must not appear in response headers');
    }
    // ...and not in anything persisted along the way (SEC-1: audit table, any column or meta).
    const rows = (await db.all(`SELECT * FROM audit`)) as any[];
    assert.ok(!JSON.stringify(rows).includes(SECRET_TOKEN), 'secret must not be persisted');
  } finally {
    up.restore();
    server.close();
  }
});

// ── SSE genuinely streams (not buffered): event 2 is only SENT after event 1 was RECEIVED ──

test('#65 mcp: SSE passthrough is incremental — the client sees event 1 while the upstream stream is still open', async (t) => {
  const { server, port } = await makeMcpBroker(t);
  let push!: (s: string | null) => void; // null = close the upstream stream
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      push = (s) => (s === null ? controller.close() : controller.enqueue(new TextEncoder().encode(s)));
    },
  });
  const up = mockUpstream(() => new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } }));
  try {
    let sawFirst: () => void;
    const gotFirst = new Promise<void>((r) => { sawFirst = r; });
    const pending = postRaw(port, '/v1/mcp', envelope(), (sofar) => {
      if (sofar.includes('event-one')) sawFirst();
    });
    push(sse('event-one'));
    // If the broker buffered the response, this never resolves (the stream is still open) → timeout.
    await Promise.race([
      gotFirst,
      new Promise((_, rej) => setTimeout(() => rej(new Error('event 1 never arrived while the stream was open — response was buffered, not streamed')), 5000).unref()),
    ]);
    push(sse('event-two'));
    push(null);
    const r = await pending;
    assert.equal(r.status, 200);
    assert.match(r.headers['content-type'] ?? '', /^text\/event-stream/);
    assert.ok(r.raw.includes('event-one') && r.raw.includes('event-two'), 'all events relayed intact');
    assert.equal(r.clean, true, 'an in-cap stream ends cleanly');
  } finally {
    up.restore();
    server.close();
  }
});

// ── every /v1/fetch gate applies, BEFORE any byte flows ──

test('#65 mcp: non-allowlisted host -> 403 before any upstream request, denied audit row matches the fetch shape', async (t) => {
  const { server, port, db } = await makeMcpBroker(t);
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope({ host: 'evil.example.com' }));
    assert.equal(r.status, 403);
    assert.deepEqual(JSON.parse(r.raw), {
      error: 'egress blocked',
      code: 'egress_blocked',
      retryable: false,
      recovery: 'fix_configuration',
    });
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope({ host: 'evil.example.com' }));
    assert.equal(viaFetch.status, 403);
    assert.deepEqual(recoveryFields(viaFetch.raw), recoveryFields(r.raw), 'fetch/MCP typed recovery drifted');
    assert.equal(up.seen.length, 0, 'the mock upstream got ZERO hits — denied before any request');
    const row = (await db.get(`SELECT meta FROM audit WHERE action='denied' ORDER BY at DESC LIMIT 1`)) as any;
    assert.deepEqual(Object.keys(JSON.parse(row.meta)).sort(), ['host', 'reason'], 'same denied meta shape as /v1/fetch (STR-4)');
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: writes off (no allowWrites) -> 405 before identity/vault/upstream', async (t) => {
  const { server, port } = await makeMcpBroker(t, { allowWrites: false });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(r.status, 405);
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: a provider without egressMethods POST stays refused even with allowWrites on', async (t) => {
  const readOnly = { ...mcpAcme, egressMethods: undefined } as Provider; // no per-provider write opt-in
  const { server, port } = await makeMcpBroker(t, { providers: [readOnly] });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(r.status, 403, 'withEgressDefaults pins the provider to GET/HEAD, so the MCP POST is denied');
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: a replayed jti is rejected on the second call (single-use identity per JSON-RPC message)', async (t) => {
  const { server, port } = await makeMcpBroker(t);
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const env = envelope(); // ONE token, used twice
    const first = await postRaw(port, '/v1/mcp', env);
    assert.equal(first.status, 200);
    const replay = await postRaw(port, '/v1/mcp', env);
    assert.equal(replay.status, 401);
    assert.equal(up.seen.length, 1, 'the replay never reached upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: identity comes from the signed token, never the body (cross-tenant probe gets its own empty owner)', async (t) => {
  const { server, port } = await makeMcpBroker(t);
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    // Attacker U2 (no credential) signs their own token but stuffs U1's ids into the body.
    const r = await postRaw(port, '/v1/mcp', envelope({
      identityToken: signIdentity(claims({ userId: 'U2' }), SECRET),
      teamId: 'T1', userId: 'U1', channel: 'C1',
    }));
    assert.equal(r.status, 409, 'resolved the token owner (U2, not connected), never the body-supplied U1');
    assert.deepEqual(JSON.parse(r.raw), {
      error: 'not connected',
      code: 'not_connected',
      retryable: false,
      recovery: 'connect',
    });
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope({
      identityToken: signIdentity(claims({ userId: 'U2' }), SECRET),
      teamId: 'T1', userId: 'U1', channel: 'C1',
    }));
    assert.equal(viaFetch.status, 409);
    assert.deepEqual(recoveryFields(viaFetch.raw), recoveryFields(r.raw), 'fetch/MCP typed recovery drifted');
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 mcp: a channel-owner assertion minted before actor offboard cannot use the retained shared credential', async (t) => {
  const owner = channelOwner('T1', 'C1');
  const { server, vault, db, port } = await makeMcpBroker(t, async (brokerDb) => {
    const channelConfig = new ChannelConfig(brokerDb);
    await writeChannelMode(channelConfig, 'T1', 'C1', 'acme', 'shared');
    await new Vault(brokerDb, KEY).upsert(owner, 'acme', {
      accessToken: SECRET_TOKEN,
      refreshToken: null,
      scopes: '',
      expiresAt: null,
      externalAccount: null,
    });
    return { channelConfig };
  });
  const staleAssertion = signIdentity(claims({
    ownerKind: 'channel',
    channelEligible: true,
  }), SECRET);
  await new Consent(db).markOffboarded({ enterpriseId: null, teamId: 'T1', userId: 'U1' });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const response = await postRaw(port, '/v1/mcp', envelope({
      handle: { provider: 'acme', owner: 'channel' },
      identityToken: staleAssertion,
    }));

    assert.equal(response.status, 409);
    assert.deepEqual(recoveryFields(response.raw), {
      code: 'interaction_state_changed',
      retryable: false,
      recovery: 'resolve_again',
    });
    assert.equal(up.seen.length, 0, 'a stale actor assertion never reaches the provider');
    assert.equal(await vault.has(owner, 'acme'), true, 'actor offboarding retains channel-owned credentials');
    assert.equal(
      (await db.get<{ n: number }>(`SELECT COUNT(*)::int AS n FROM audit WHERE action='inject'`))?.n,
      0,
      'a refused use emits no successful injection audit',
    );
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 fetch/MCP: policy denial has stable admin recovery metadata before credential use', async (t) => {
  const policy = new Policy({ acme: { defaultAllow: true, denyChannels: ['C1'] } });
  const { server, port } = await makeMcpBroker(t, { policy });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 403);
      assert.deepEqual(JSON.parse(response.raw), {
        error: 'policy denies this provider in this channel',
        code: 'policy_denied',
        retryable: false,
        recovery: 'contact_admin',
      });
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 fetch/MCP: channel tool-disabled denial has stable admin recovery metadata', async (t) => {
  const { server, port } = await makeMcpBroker(t, async (db) => {
    const channelTools = new ChannelTools(db);
    // Any row configures the channel as an allowlist; acme is deliberately absent/disabled.
    await setChannelToolEnabled(channelTools, 'T1', 'C1', 'other', true);
    return { channelTools };
  });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 403);
      assert.deepEqual(JSON.parse(response.raw), {
        error: 'provider is not enabled in this channel',
        code: 'tool_disabled',
        retryable: false,
        recovery: 'contact_admin',
      });
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

// ── stream ceilings: terminated, never a clean end ──

test('#65 mcp: maxStreamBytes terminates the stream — client receives <= cap, socket torn down, upstream aborted', async (t) => {
  const { server, port } = await makeMcpBroker(t, { maxStreamBytes: 64 });
  const chunk = new TextEncoder().encode('x'.repeat(16));
  const up = mockUpstream(() => new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 100; i++) controller.enqueue(chunk); // 1600 bytes >> the 64-byte ceiling
        controller.close();
      },
    }),
    { status: 200, headers: { 'content-type': 'text/event-stream' } },
  ));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(r.status, 200, 'headers were already flushed when the ceiling hit');
    assert.ok(Buffer.byteLength(r.raw) <= 64, `client must never receive a byte past the cap (got ${Buffer.byteLength(r.raw)})`);
    assert.equal(r.clean, false, 'a truncated stream must NOT end cleanly (no fake-complete response)');
    assert.equal(up.seen[0].signal?.aborted, true, 'the upstream fetch was aborted at the ceiling');
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: maxStreamMs aborts a stream that never ends', async (t) => {
  const { server, port } = await makeMcpBroker(t, { maxStreamMs: 80 });
  const up = mockUpstream(() => new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(sse('hello'))); // one event, then silence forever
      },
    }),
    { status: 200, headers: { 'content-type': 'text/event-stream' } },
  ));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(r.status, 200);
    assert.ok(r.raw.includes('hello'), 'bytes before the deadline still flowed');
    assert.equal(r.clean, false, 'the hung stream was torn down, not cleanly ended');
    assert.equal(up.seen[0].signal?.aborted, true, 'the upstream fetch was aborted by the timer');
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 fetch/MCP: pre-header timeouts expose conservative unknown-outcome metadata', async (t) => {
  const { server, port } = await makeMcpBroker(t, { maxStreamMs: 80, fetchDeadlineMs: 80 });
  // Keep Node's general socket-idle guard above the route deadlines; this test targets the typed
  // route timeout, not the server-level hard destroy that intentionally has no JSON response.
  server.timeout = 1_000;
  const up = mockUpstream((_url, init) => new Promise<Response>((_resolve, reject) => {
    const signal = init.signal as AbortSignal;
    const abort = () => reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  }));
  try {
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 504);
      assert.equal(response.clean, true, 'a pre-header timeout is a complete JSON error, not a torn stream');
      assert.deepEqual(JSON.parse(response.raw), {
        error: 'upstream timed out',
        code: 'upstream_timeout',
        retryable: false,
        recovery: 'retry_later',
      });
    }
    assert.equal(up.seen.length, 2);
    assert.ok(up.seen.every((seen) => seen.signal?.aborted), 'each deadline closes its upstream request');
  } finally {
    up.restore();
    server.close();
  }
});

// ── #110 composition: a provider egressResponse.maxBytes stricter than the stream ceiling wins ──

test('#65 mcp: provider egressResponse.maxBytes (stricter) denies with 413 before any byte is relayed', async (t) => {
  const capped = { ...mcpAcme, egressResponse: { maxBytes: 32 } } as Provider;
  const { server, port } = await makeMcpBroker(t, { providers: [capped] }); // broker ceiling stays 8 MiB
  const up = mockUpstream(() => new Response('x'.repeat(100), { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(r.status, 413, 'the injector withheld the over-cap response before the relay started');
    assert.deepEqual(JSON.parse(r.raw), {
      error: 'response blocked',
      code: 'response_blocked',
      retryable: false,
      recovery: 'fix_configuration',
    });
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    assert.equal(viaFetch.status, 413);
    assert.deepEqual(recoveryFields(viaFetch.raw), recoveryFields(r.raw), 'fetch/MCP typed recovery drifted');
    assert.equal(r.clean, true, 'a pre-stream denial is a normal JSON error, not a torn stream');
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: fetch and MCP keep resolver failure metadata identical and secret-free', async (t) => {
  const resolverSecret = 'resolver failure with ghp_never_render_this';
  const { server, port, vault } = await makeMcpBroker(t, {
    resolvers: { 'aws-sm': async () => { throw new Error(resolverSecret); } },
  });
  await vault.reference(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    source: 'aws-sm',
    secretRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/mcp',
  });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 502);
      assert.deepEqual(recoveryFields(response.raw), {
        code: 'resolver_failed', retryable: true, recovery: 'retry_later',
      });
      assert.ok(!response.raw.includes(resolverSecret));
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: malformed resolver configuration is distinct from a runtime outage on both routes', async (t) => {
  const malformed = 'arn:aws:secretsmanager:malformed-ghp_reference_sentinel';
  let resolverCalls = 0;
  const { server, port, vault } = await makeMcpBroker(t, {
    resolvers: { 'aws-sm': async () => { resolverCalls++; return SECRET_TOKEN; } },
  });
  await vault.reference(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    source: 'aws-sm',
    secretRef: malformed,
  });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 502);
      assert.deepEqual(recoveryFields(response.raw), {
        code: 'resolver_configuration_error', retryable: false, recovery: 'fix_configuration',
      });
      assert.ok(!response.raw.includes(malformed));
    }
    assert.equal(resolverCalls, 0);
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: invalid fulfilled resolver values fail closed on fetch and MCP', async (t) => {
  let resolved: unknown;
  const { server, port, vault } = await makeMcpBroker(t, {
    resolvers: { 'aws-sm': (async () => resolved) as any },
  });
  const reference = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/invalid-wire-output';
  await vault.reference(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    source: 'aws-sm',
    secretRef: reference,
  });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    for (const value of [undefined, 42, '', { secret: 'ghp_invalid_wire_resolver' }] as const) {
      resolved = value;
      const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
      const viaMcp = await postRaw(port, '/v1/mcp', envelope());
      for (const response of [viaFetch, viaMcp]) {
        assert.equal(response.status, 502);
        assert.deepEqual(recoveryFields(response.raw), {
          code: 'resolver_configuration_error', retryable: false, recovery: 'fix_configuration',
        });
        assert.ok(!response.raw.includes(reference));
        assert.ok(!response.raw.includes('ghp_invalid_wire_resolver'));
      }
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: a resolver deadline is retryable on fetch/MCP because provider egress never began', async (t) => {
  const { server, port, vault } = await makeMcpBroker(t, {
    fetchDeadlineMs: 60,
    maxStreamMs: 60,
    resolvers: { 'aws-sm': async () => await new Promise<string>(() => undefined) },
  });
  server.timeout = 1_000;
  await vault.reference(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    source: 'aws-sm',
    secretRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:vouchr/hung-wire-resolver',
  });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 502);
      assert.deepEqual(JSON.parse(response.raw), {
        error: 'credential resolution failed',
        code: 'resolver_failed',
        retryable: true,
        recovery: 'retry_later',
      });
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: token credential, configuration, and transient failures keep fetch/MCP parity', async (t) => {
  const refreshing = { ...mcpAcme, refresh: 'rotating' as const } as Provider;
  const { server, port, vault } = await makeMcpBroker(t, { providers: [refreshing] });
  const refreshSecret = 'refresh_ghp_token_wire_secret';
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: 'expired_access_secret',
    refreshToken: refreshSecret,
    scopes: 'x',
    expiresAt: Date.now() - 1_000,
    externalAccount: null,
  });
  const networkSentinel = 'network_ghp_token_endpoint_sentinel';
  let respond: () => Response | Promise<Response>;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request) => {
    assert.equal(String(url), 'https://acme.example/token', 'provider egress must not run after refresh failure');
    return await respond();
  }) as any;
  try {
    const cases = [
      {
        name: 'invalid_grant',
        response: () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }),
        fields: { code: 'token_endpoint_failed', retryable: false, recovery: 'connect' },
      },
      {
        name: 'invalid_client',
        response: () => new Response(JSON.stringify({ error: 'invalid_client' }), { status: 400 }),
        fields: { code: 'token_endpoint_failed', retryable: false, recovery: 'fix_configuration' },
      },
      {
        name: '429',
        response: () => new Response('slow down', { status: 429 }),
        fields: { code: 'token_endpoint_failed', retryable: true, recovery: 'retry_later' },
      },
      {
        name: '503',
        response: () => new Response('unavailable', { status: 503 }),
        fields: { code: 'token_endpoint_failed', retryable: true, recovery: 'retry_later' },
      },
      {
        name: 'network',
        response: async () => { throw new TypeError(networkSentinel); },
        fields: { code: 'token_endpoint_failed', retryable: true, recovery: 'retry_later' },
      },
    ] as const;
    for (const scenario of cases) {
      respond = scenario.response;
      const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
      const viaMcp = await postRaw(port, '/v1/mcp', envelope());
      for (const response of [viaFetch, viaMcp]) {
        assert.equal(response.status, 502, scenario.name);
        assert.deepEqual(recoveryFields(response.raw), scenario.fields, scenario.name);
        assert.ok(!response.raw.includes(refreshSecret), scenario.name);
        assert.ok(!response.raw.includes(networkSentinel), scenario.name);
      }
    }
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});

test('#194 typed recovery: pre-handle database failures return fixed internal metadata on both routes', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const sentinel = 'postgres_ghp_internal_sentinel';
  const failingDb = new Proxy(db, {
    get(target, property) {
      if (property === 'run') return async () => { throw new Error(sentinel); };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const server = createBroker({
    providers: [mcpAcme], vault, audit, db: failingDb, identitySecret: identityConfig(SECRET), allowWrites: true,
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 500);
      assert.deepEqual(JSON.parse(response.raw), {
        error: 'internal error', code: 'internal_error', retryable: false, recovery: 'contact_admin',
      });
      assert.ok(!response.raw.includes(sentinel));
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: vault/KMS failures stay secret-free and aligned across both routes', async (t) => {
  const db = await openTestDb(t);
  const vault = new Vault(db, KEY);
  const audit = new Audit(db);
  await vault.upsert(userOwner({ enterpriseId: null, teamId: 'T1', userId: 'U1' }), 'acme', {
    accessToken: SECRET_TOKEN, refreshToken: null, scopes: '', expiresAt: null, externalAccount: null,
  });
  const sentinel = 'kms_ghp_internal_sentinel';
  const failingVault = new Proxy(vault, {
    get(target, property) {
      if (property === 'get') return async () => { throw new Error(sentinel); };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const server = createBroker({
    providers: [mcpAcme], vault: failingVault, audit, db, identitySecret: identityConfig(SECRET), allowWrites: true,
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 502);
      assert.deepEqual(recoveryFields(response.raw), {
        code: 'internal_error', retryable: false, recovery: 'contact_admin',
      });
      assert.ok(!response.raw.includes(sentinel));
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: fetch and MCP keep approval metadata identical without exposing the body', async (t) => {
  const approvalProvider = { ...mcpAcme, approval: { approver: 'self' as const } } as Provider;
  const { server, port } = await makeMcpBroker(t, { providers: [approvalProvider] });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const bodySecret = 'request-body-ghp_never_render_this';
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope({ body: bodySecret }));
    const viaMcp = await postRaw(port, '/v1/mcp', envelope({ body: bodySecret }));
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 403);
      const parsed = JSON.parse(response.raw);
      assert.deepEqual(recoveryFields(response.raw), {
        code: 'approval_required', retryable: false, recovery: 'request_approval',
      });
      assert.equal(typeof parsed.approvalId, 'string');
      assert.ok(!response.raw.includes(bodySecret));
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: fetch and MCP keep rate-limit metadata aligned with millisecond hints', async (t) => {
  const limited = { ...mcpAcme, rateLimit: { perMinute: 1, burst: 1 } } as Provider;
  const { server, port } = await makeMcpBroker(t, { providers: [limited] });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const warm = await postRaw(port, '/v1/fetch', fetchEnvelope());
    assert.equal(warm.status, 200);
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 429);
      const parsed = JSON.parse(response.raw);
      assert.equal(parsed.code, 'rate_limited');
      assert.equal(parsed.retryable, true);
      assert.equal(parsed.recovery, 'retry_later');
      assert.ok(Number.isSafeInteger(parsed.retryAfterMs) && parsed.retryAfterMs > 0);
    }
    assert.equal(up.seen.length, 1, 'both denied requests stopped before upstream');
  } finally {
    up.restore();
    server.close();
  }
});

test('#194 typed recovery: fetch and MCP mask an extension throw behind the same internal code', async (t) => {
  const extensionSecret = 'inject failure with ghp_never_render_this';
  const throwing = {
    ...mcpAcme,
    inject: () => { throw new Error(extensionSecret); },
  } as Provider;
  const { server, port } = await makeMcpBroker(t, { providers: [throwing] });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 502);
      assert.deepEqual(recoveryFields(response.raw), {
        code: 'internal_error', retryable: false, recovery: 'contact_admin',
      });
      assert.ok(!response.raw.includes(extensionSecret));
    }
    assert.equal(up.seen.length, 0);
  } finally {
    up.restore();
    server.close();
  }
});

// ── audit parity + statelessness ──

test('#65 mcp: the inject audit row is indistinguishable in shape from a /v1/fetch write (STR-4)', async (t) => {
  const writeAcme = { ...mcpAcme, egressAllow: ['mcp.acme.example', 'api.acme.example'] } as Provider;
  const { server, port, db } = await makeMcpBroker(t, { providers: [writeAcme] });
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    await postRaw(port, '/v1/mcp', envelope());
    const viaFetch = await postRaw(port, '/v1/fetch', {
      handle: { provider: 'acme', owner: 'user' }, identityToken: signIdentity(claims(), SECRET),
      method: 'POST', path: '/mcp', body: '{}',
    });
    assert.equal(viaFetch.status, 200);
    const rows = (await db.all(`SELECT meta FROM audit WHERE action='inject' ORDER BY at`)) as any[];
    assert.equal(rows.length, 2);
    const [mcpMeta, fetchMeta] = rows.map((r) => JSON.parse(r.meta));
    assert.deepEqual(Object.keys(mcpMeta).sort(), Object.keys(fetchMeta).sort(), 'same inject meta keys as /v1/fetch');
    assert.equal(mcpMeta.method, 'POST');
    assert.equal(mcpMeta.host, 'mcp.acme.example');
    assert.equal(mcpMeta.channel, 'C1');
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: the broker is stateless — no MCP/session table, the session id persisted nowhere', async (t) => {
  const { server, port, db } = await makeMcpBroker(t);
  const up = mockUpstream(() => new Response('{}', {
    status: 200, headers: { 'content-type': 'application/json', 'mcp-session-id': 'sess-STATELESS-42' },
  }));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope({ headers: { 'mcp-session-id': 'sess-STATELESS-42' } }));
    assert.equal(r.headers['mcp-session-id'], 'sess-STATELESS-42', 'the id round-trips…');
    const tables = (await db.all(`SELECT table_name AS name FROM information_schema.tables WHERE table_schema = current_schema() AND (table_name LIKE '%mcp%' OR table_name LIKE '%stream%')`)) as any[];
    assert.deepEqual(tables, [], '…but no MCP/stream state table exists');
    const persisted = (await db.get(`SELECT count(*) AS n FROM audit WHERE meta LIKE '%sess-STATELESS-42%'`)) as any;
    assert.equal(persisted.n, 0, 'the session id is relayed, never stored');
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: a client that vanishes before headers flush is torn down cleanly — no crash, broker keeps serving', async (t) => {
  const { server, port } = await makeMcpBroker(t);
  // Gate the upstream response so we can destroy the CLIENT socket while the broker is mid-fetch:
  // when released, the relay reaches writeHead with the client already gone. A regression that
  // rethrows out of the relay would double-writeHead in the outer catch and crash the process as
  // an unhandled rejection — which fails this whole test run, deterministically.
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const up = mockUpstream(async () => {
    await gate;
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  try {
    const data = Buffer.from(JSON.stringify(envelope()));
    const req = http.request({
      host: '127.0.0.1', port, path: '/v1/mcp', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': data.length },
    });
    req.on('error', () => undefined); // the deliberate destroy below surfaces here; expected
    req.end(data);
    // Wait until the broker actually called upstream (all gates passed, fetch pending on the gate)…
    for (let i = 0; i < 400 && up.seen.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assert.equal(up.seen.length, 1, 'the gated upstream call is in flight');
    // …then kill the client and let the close propagate before releasing the upstream response.
    req.destroy();
    await new Promise((r) => setTimeout(r, 20));
    release();
    // The broker must still be alive and serving: a fresh request works end to end.
    const ok = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(ok.status, 200);
    assert.equal(ok.raw, '{}');
  } finally {
    up.restore();
    server.close();
  }
});

// ── the declarative per-provider opt-in (provider.mcp) ──

test('#65 mcp: a POST-enabled provider WITHOUT the mcp knob is refused — /v1/mcp is opt-in, not implied by /v1/fetch writes', async (t) => {
  const noKnob = { ...mcpAcme, mcp: undefined } as Provider; // POST-capable for /v1/fetch, NOT MCP-declared
  const { server, port, db } = await makeMcpBroker(t, { providers: [noKnob] });
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    const r = await postRaw(port, '/v1/mcp', envelope());
    assert.equal(r.status, 403);
    assert.deepEqual(JSON.parse(r.raw), {
      error: 'provider is not enabled for /v1/mcp',
      code: 'egress_blocked',
      retryable: false,
      recovery: 'fix_configuration',
    });
    assert.equal(up.seen.length, 0, 'denied before the vault/upstream — zero hits');
    const row = (await db.get(`SELECT meta FROM audit WHERE action='denied' ORDER BY at DESC LIMIT 1`)) as any;
    assert.deepEqual(JSON.parse(row.meta), { host: 'mcp.acme.example', reason: 'mcp-not-enabled' }, 'egress-denial meta shape (STR-4)');
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: a path outside mcp.paths is refused — same matcher as egressPaths, encoded separators fail closed', async (t) => {
  const { server, port } = await makeMcpBroker(t); // mcpAcme declares mcp.paths: ['/mcp']
  const up = mockUpstream(() => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    for (const path of ['/admin', '/mcp-evil', '/mcp/..%2f..%2fsecrets', '/mcp/%252e%252e%252fadmin']) {
      const r = await postRaw(port, '/v1/mcp', envelope({ path }));
      assert.equal(r.status, 403, `path ${path} must be refused`);
      assert.deepEqual(recoveryFields(r.raw), {
        code: 'egress_blocked', retryable: false, recovery: 'fix_configuration',
      });
    }
    assert.equal(up.seen.length, 0, 'path denials happen before anything goes upstream');
    // Prefix-rule sanity (shared matcher semantics): a subpath of the declared endpoint is allowed.
    const ok = await postRaw(port, '/v1/mcp', envelope({ path: '/mcp/session' }));
    assert.equal(ok.status, 200);
    assert.equal(up.seen.length, 1);
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: a text/plain upstream reflecting the injected Authorization is withheld unread (default content-type gate)', async (t) => {
  const { server, port } = await makeMcpBroker(t);
  // The review probe: an allowlisted-but-hostile MCP endpoint echoing the request Authorization
  // header into a text/plain error body. The default mcp.allowContentTypes gate must stop it.
  const up = mockUpstream((_url, init) => new Response(
    `error: bad token ${new Headers(init?.headers).get('authorization')}`,
    { status: 200, headers: { 'content-type': 'text/plain' } },
  ));
  try {
    const viaMcp = await postRaw(port, '/v1/mcp', envelope());
    const viaFetch = await postRaw(port, '/v1/fetch', fetchEnvelope());
    for (const response of [viaFetch, viaMcp]) {
      assert.equal(response.status, 502);
      assert.deepEqual(JSON.parse(response.raw), {
        error: 'disallowed content-type',
        code: 'response_blocked',
        retryable: false,
        recovery: 'fix_configuration',
      });
      assert.ok(!response.raw.includes(SECRET_TOKEN), 'the reflected credential never reaches the caller');
    }
  } finally {
    up.restore();
    server.close();
  }
});

test('#65 mcp: defineProvider rejects an invalid mcp knob at definition time', () => {
  const base = {
    id: 'm', authorizeUrl: 'https://x.example/a', tokenUrl: 'https://x.example/t', scopesDefault: [],
    egressAllow: ['x.example'], refresh: 'none' as const, pkce: false, clientId: 'i', clientSecret: 's',
  };
  assert.throws(() => defineProvider({ ...base, mcp: { paths: [] } }), /mcp\.paths/);
  assert.throws(() => defineProvider({ ...base, mcp: { paths: [' '] } }), /mcp\.paths/);
  assert.throws(() => defineProvider({ ...base, mcp: { paths: [42 as unknown as string] } }), /mcp\.paths/);
  assert.throws(() => defineProvider({ ...base, mcp: { paths: ['/mcp'], allowContentTypes: [] } }), /mcp\.allowContentTypes/);
  assert.throws(() => defineProvider({ ...base, mcp: { paths: ['/mcp'], allowContentTypes: [' '] } }), /mcp\.allowContentTypes/);
  assert.ok(defineProvider({ ...base, mcp: { paths: ['/mcp'] } }).mcp);
});

// ── construction-time ceiling validation (a NaN cap would silently fail open) ──

test('#65 mcp: createBroker rejects NaN/Infinity/zero/negative stream ceilings; valid values construct', async (t) => {
  const db = await openTestDb(t);
  const base = { providers: [mcpAcme], vault: new Vault(db, KEY), audit: new Audit(db), db, identitySecret: identityConfig(SECRET) };
  try {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1]) {
      assert.throws(() => createBroker({ ...base, maxStreamBytes: bad }), /maxStreamBytes/, `maxStreamBytes: ${bad} must be rejected`);
      assert.throws(() => createBroker({ ...base, maxStreamMs: bad }), /maxStreamMs/, `maxStreamMs: ${bad} must be rejected`);
    }
    assert.ok(createBroker({ ...base, maxStreamBytes: 1024, maxStreamMs: 1000 }), 'valid ceilings still construct');
  } finally {
    await db.close();
  }
});

// ── MCP spec: unsupported GET listening stream / DELETE termination answer 405, not 404 ──

test('#65 mcp: GET and DELETE on /v1/mcp -> 405 with Allow: POST, no provider gates, zero upstream hits', async (t) => {
  const { server, port } = await makeMcpBroker(t);
  const up = mockUpstream(() => new Response('{}', { status: 200 }));
  try {
    for (const method of ['GET', 'DELETE']) {
      const r = await new Promise<{ status: number; allow?: string; raw: string }>((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path: '/v1/mcp', method }, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, allow: res.headers.allow, raw: Buffer.concat(chunks).toString('utf8') }));
        });
        req.on('error', reject);
        req.end();
      });
      assert.equal(r.status, 405, `${method} must answer 405 (a 404 reads as "session ended" to MCP clients)`);
      assert.equal(r.allow, 'POST');
    }
    assert.equal(up.seen.length, 0, 'nothing went upstream');
  } finally {
    up.restore();
    server.close();
  }
});
