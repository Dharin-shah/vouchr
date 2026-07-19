import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  OAUTH_RESPONSE_MAX_BYTES,
  ResponseBodyTooLargeError,
  awaitWithSignal,
  disposableDeadline,
  readResponseTextCapped,
} from '../src/core/httpBounds';
import { MAX_TIMER_MS } from '../src/core/options';
import {
  ProviderRegistry,
  databricks,
  defineProvider,
  github,
  normalizeAccountLabel,
  type Provider,
} from '../src/core/providers';
import {
  exchangeCode,
  normalizeGrantedScopes,
  refreshToken,
  revokeToken,
  TokenEndpointError,
} from '../src/core/tokens';
import { handleOAuthCallback } from '../src/core/oauthCallback';
import { ConnectionHandle } from '../src/core/injector';
import { UpstreamTimeoutError } from '../src/core/errors';
import { userOwner } from '../src/core/owner';
import type { SlackIdentity } from '../src/core/identity';

const oauthProvider = () => defineProvider({
  id: 'acme',
  authorizeUrl: 'https://acme.example/authorize',
  tokenUrl: 'https://acme.example/token',
  scopesDefault: ['read'],
  egressAllow: ['api.acme.example'],
  refresh: 'rotating',
  pkce: true,
  clientId: 'client',
  clientSecret: 'secret',
});

const IDENTITY: SlackIdentity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
const OWNER = userOwner(IDENTITY);
const quietAudit = { record: async () => undefined } as any;

function fakeVault(over: Record<string, unknown> = {}) {
  const credential = {
    source: 'vault', accessToken: 'old', refreshToken: null, secretRef: null, scopes: 'read',
    expiresAt: null, externalAccount: null, dryRun: false,
    ...over,
  };
  const vault: any = {
    crossProcessRefresh: false,
    liveId: async () => '00000000-0000-4000-8000-000000000001',
    get: async () => credential,
    touch: async () => undefined,
    updateTokens: async () => undefined,
    withRefreshLock: async (_owner: unknown, _provider: string, fn: (locked: any) => Promise<unknown>) => fn(vault),
  };
  return vault;
}

function connectionHandle(provider: Provider, vault: any, deadlineMs: number): ConnectionHandle {
  return new ConnectionHandle(
    provider, OWNER, IDENTITY, vault, quietAudit, {}, new Map(), () => {}, () => {}, null,
    undefined, () => {}, null, null, false, deadlineMs,
  );
}

function hangUntilAbort(signal: AbortSignal | undefined, onAbort: () => void): Promise<Response> {
  return new Promise((_resolve, reject) => {
    const abort = () => {
      onAbort();
      reject(signal?.reason ?? new DOMException('The operation was aborted', 'AbortError'));
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
  });
}

test('http bounds: fixed and chunked response caps cancel before retaining an over-cap body (#209)', async () => {
  let fixedCancelled = false;
  const fixed = new Response(new ReadableStream({
    cancel() { fixedCancelled = true; },
  }), { headers: { 'content-length': '6' } });
  await assert.rejects(readResponseTextCapped(fixed, 5), ResponseBodyTooLargeError);
  assert.equal(fixedCancelled, true, 'declared over-cap bodies are cancelled before a read');

  let chunkedCancelled = false;
  let pulls = 0;
  const chunked = new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++;
      controller.enqueue(new Uint8Array(4));
    },
    cancel() { chunkedCancelled = true; },
  }));
  await assert.rejects(readResponseTextCapped(chunked, 5), ResponseBodyTooLargeError);
  assert.equal(chunkedCancelled, true);
  assert.ok(pulls <= 2, `stream must stop at the first over-cap chunk; pulls=${pulls}`);
});

test('http bounds: caller cancellation and deadline are composed and disposable (#209)', async () => {
  assert.throws(() => disposableDeadline(MAX_TIMER_MS + 1), /HTTP deadline/);
  assert.throws(() => disposableDeadline(1.5), /HTTP deadline/);

  const caller = new AbortController();
  const originalRemove = caller.signal.removeEventListener.bind(caller.signal);
  let removedListeners = 0;
  (caller.signal as any).removeEventListener = (...args: Parameters<AbortSignal['removeEventListener']>) => {
    removedListeners++;
    return originalRemove(...args);
  };
  const composed = disposableDeadline(1_000, caller.signal);
  const reason = new DOMException('caller left', 'AbortError');
  const originalClearTimeout = globalThis.clearTimeout;
  let clearedTimers = 0;
  globalThis.clearTimeout = ((timer: ReturnType<typeof setTimeout>) => {
    clearedTimers++;
    return originalClearTimeout(timer);
  }) as typeof clearTimeout;
  try {
    caller.abort(reason);
  } finally {
    globalThis.clearTimeout = originalClearTimeout;
    delete (caller.signal as any).removeEventListener;
  }
  assert.equal(composed.signal.aborted, true);
  assert.equal(composed.signal.reason, reason);
  assert.equal(composed.timedOut(), false);
  assert.equal(clearedTimers, 1, 'caller abort clears the still-pending deadline timer immediately');
  assert.equal(removedListeners, 1, 'caller abort removes its composed listener immediately');
  composed.dispose();
  composed.dispose(); // idempotent cleanup

  const timed = disposableDeadline(5);
  await new Promise<void>((resolve) => timed.signal.addEventListener('abort', () => resolve(), { once: true }));
  assert.equal(timed.timedOut(), true);
  assert.equal((timed.signal.reason as DOMException).name, 'TimeoutError');
  timed.dispose();
});

test('http bounds: abort racing escapes ignored cancellation and removes its listener (#209)', async () => {
  const controller = new AbortController();
  const originalRemove = controller.signal.removeEventListener.bind(controller.signal);
  let removedListeners = 0;
  (controller.signal as any).removeEventListener = (...args: Parameters<AbortSignal['removeEventListener']>) => {
    removedListeners++;
    return originalRemove(...args);
  };
  try {
    const waiting = awaitWithSignal(new Promise<string>(() => {}), controller.signal);
    const reason = new DOMException('caller left', 'AbortError');
    controller.abort(reason);
    await assert.rejects(waiting, (error: unknown) => error === reason);
    assert.equal(removedListeners, 1);
  } finally {
    delete (controller.signal as any).removeEventListener;
  }
});

test('provider oauthTimeoutMs validates and configures token, revoke, and built-in probe deadlines (#209)', async () => {
  for (const timeout of [0, -1, 1.5, MAX_TIMER_MS + 1]) {
    assert.throws(() => defineProvider({ ...oauthProvider(), oauthTimeoutMs: timeout }), /oauthTimeoutMs/);
  }

  const timeoutMs = 15;
  assert.equal(
    databricks({ host: 'https://workspace.cloud.databricks.com', clientId: 'client', oauthTimeoutMs: timeoutMs }).oauthTimeoutMs,
    timeoutMs,
    'the hand-built Databricks factory must preserve the same provider-local deadline',
  );
  const provider = defineProvider({
    ...oauthProvider(),
    oauthTimeoutMs: timeoutMs,
    revokeTarget: 'access',
    revoke: async (_provider, _token, signal) => {
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener('abort', () => resolve(), { once: true });
      });
    },
  });
  const realFetch = globalThis.fetch;
  let tokenAborted = false;
  try {
    globalThis.fetch = ((_url: unknown, init: RequestInit) =>
      hangUntilAbort(init.signal ?? undefined, () => { tokenAborted = true; })) as any;
    await assert.rejects(
      exchangeCode(provider, 'code', 'https://app.example/callback', 'verifier'),
      (error: unknown) => error instanceof TokenEndpointError
        && error.kind === 'transient'
        && !error.definitive,
    );
    assert.equal(tokenAborted, true);

    await assert.rejects(revokeToken(provider, 'access'), /timed out/);

    let probeAborted = false;
    const probe = github({ clientId: 'client', clientSecret: 'secret', oauthTimeoutMs: timeoutMs }).accountProbe!;
    globalThis.fetch = ((_url: unknown, init: RequestInit) =>
      hangUntilAbort(init.signal ?? undefined, () => { probeAborted = true; })) as any;
    assert.equal(await probe('access'), null);
    assert.equal(probeAborted, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth token responses: fixed/chunked bodies are capped and caller cancellation reaches fetch (#209)', async () => {
  const provider = oauthProvider();
  const realFetch = globalThis.fetch;
  try {
    let fixedCancelled = false;
    globalThis.fetch = (async () => new Response(new ReadableStream({
      cancel() { fixedCancelled = true; },
    }), { status: 200, headers: { 'content-length': String(OAUTH_RESPONSE_MAX_BYTES + 1) } })) as any;
    await assert.rejects(
      exchangeCode(provider, 'code', 'https://app.example/callback', 'verifier'),
      (error: unknown) => error instanceof TokenEndpointError
        && error.kind === 'configuration'
        && !error.message.includes(String(OAUTH_RESPONSE_MAX_BYTES)),
    );
    assert.equal(fixedCancelled, true);

    let chunkedCancelled = false;
    globalThis.fetch = (async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new Uint8Array(8 * 1024)); },
      cancel() { chunkedCancelled = true; },
    }), { status: 200 })) as any;
    await assert.rejects(
      exchangeCode(provider, 'code', 'https://app.example/callback', 'verifier'),
      (error: unknown) => error instanceof TokenEndpointError
        && error.kind === 'configuration',
    );
    assert.equal(chunkedCancelled, true);

    const caller = new AbortController();
    let tokenSignal: AbortSignal | undefined;
    globalThis.fetch = ((_url: unknown, init: RequestInit) => {
      tokenSignal = init.signal ?? undefined;
      return new Promise((_resolve, reject) => {
        tokenSignal?.addEventListener('abort', () => reject(tokenSignal?.reason), { once: true });
      });
    }) as any;
    const pending = refreshToken(provider, 'refresh', caller.signal);
    caller.abort(new DOMException('caller left', 'AbortError'));
    await assert.rejects(pending, (error: any) => error?.name === 'AbortError');
    assert.equal(tokenSignal?.aborted, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth token errors: an over-cap 400 body is cancelled and never reflected (#209)', async () => {
  const provider = oauthProvider();
  const realFetch = globalThis.fetch;
  let cancelled = false;
  try {
    globalThis.fetch = (async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new Uint8Array(8 * 1024)); },
      cancel() { cancelled = true; },
    }), { status: 400 })) as any;
    await assert.rejects(
      exchangeCode(provider, 'code', 'https://app.example/callback', 'verifier'),
      (error: unknown) => error instanceof TokenEndpointError
        && error.definitive
        && !error.message.includes('8192'),
    );
    assert.equal(cancelled, true, 'discarded error bodies are cancelled at the streamed cap');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth token responses: malformed typed fields are rejected before vault use (SEC-4, #209)', async () => {
  const provider = oauthProvider();
  const invalid = [
    { access_token: '' },
    { access_token: { nested: 'secret' } },
    { access_token: 'access', refresh_token: '' },
    { access_token: 'access', refresh_token: { bad: true } },
    { access_token: 'access', scope: ['read'] },
    { access_token: 'access', expires_in: -1 },
    { access_token: 'access', expires_in: '3600' },
    { access_token: 'access', expires_in: Number.MAX_VALUE },
  ];
  const realFetch = globalThis.fetch;
  try {
    for (const body of invalid) {
      globalThis.fetch = (async () => new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as any;
      await assert.rejects(
        exchangeCode(provider, 'code', 'https://app.example/callback', 'verifier'),
        /Token endpoint returned/,
      );
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('built-in probes cap chunked JSON and normalize labels (#209)', async () => {
  const probe = github({ clientId: 'client', clientSecret: 'secret' }).accountProbe!;
  const realFetch = globalThis.fetch;
  try {
    let probeCancelled = false;
    globalThis.fetch = (async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new Uint8Array(8 * 1024)); },
      cancel() { probeCancelled = true; },
    }), { status: 200 })) as any;
    assert.equal(await probe('access'), null);
    assert.equal(probeCancelled, true);

    globalThis.fetch = (async () => new Response(JSON.stringify({ login: { not: 'a string' } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as any;
    assert.equal(await probe('access'), null);

  } finally {
    globalThis.fetch = realFetch;
  }
});

test('GitHub revoke releases response bodies on 200, already-gone 404, and error 500 (#209)', async () => {
  const provider = github({ clientId: 'client', clientSecret: 'secret' });
  const realFetch = globalThis.fetch;
  try {
    for (const status of [200, 404, 500]) {
      let cancelled = false;
      globalThis.fetch = (async () => new Response(new ReadableStream({
        cancel() { cancelled = true; },
      }), { status })) as any;
      if (status === 500) {
        await assert.rejects(revokeToken(provider, 'access'), /HTTP 500/);
      } else {
        await revokeToken(provider, 'access');
      }
      assert.equal(cancelled, true, `GitHub revoke must release its HTTP ${status} body`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('revoke timeout rejects unsafe Node timer values before any outbound work (#209)', async () => {
  const provider = github({ clientId: 'client', clientSecret: 'secret' });
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => { calls++; return new Response(null, { status: 200 }); }) as any;
  try {
    for (const timeout of [0, -1, 1.5, MAX_TIMER_MS + 1]) {
      await assert.rejects(revokeToken(provider, 'access', timeout), /Revoke timeout/);
    }
    assert.equal(calls, 0, 'invalid timers are rejected before a revoke hook can run');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('account labels are one-line, trimmed, type-safe, and UTF-8 byte bounded (#209)', () => {
  assert.equal(normalizeAccountLabel('  octocat  '), 'octocat');
  assert.equal(normalizeAccountLabel(''), null);
  assert.equal(normalizeAccountLabel('   '), null);
  assert.equal(normalizeAccountLabel({ account: 'octocat' }), null);
  assert.equal(normalizeAccountLabel('first\nsecond'), null);
  assert.equal(normalizeAccountLabel('first\u2028second'), null);
  assert.equal(normalizeAccountLabel('first\u2029second'), null);
  assert.equal(normalizeAccountLabel('😀'.repeat(128)), '😀'.repeat(128)); // exactly 512 UTF-8 bytes
  assert.equal(normalizeAccountLabel('😀'.repeat(129)), null);
});

test('granted OAuth scopes are canonical, bounded, and cannot contain credential material (SEC-1, #209)', () => {
  assert.equal(normalizeGrantedScopes('read write:repo'), 'read write:repo');
  assert.equal(normalizeGrantedScopes(' read'), null);
  assert.equal(normalizeGrantedScopes('read  write'), null);
  assert.equal(normalizeGrantedScopes('read\nwrite'), null);
  assert.equal(normalizeGrantedScopes('x'.repeat(4 * 1024 + 1)), null);
  assert.equal(normalizeGrantedScopes('read tok_secret write', ['tok_secret']), null);
});

test('ConnectionHandle composes a supplied non-aborting caller signal with its finite deadline (#209)', async () => {
  const provider = defineProvider({ ...oauthProvider(), refresh: 'none' });
  const caller = new AbortController();
  const realFetch = globalThis.fetch;
  let upstreamSignal: AbortSignal | undefined;
  let aborted = 0;
  try {
    globalThis.fetch = ((_url: unknown, init: RequestInit) => {
      upstreamSignal = init.signal ?? undefined;
      return hangUntilAbort(upstreamSignal, () => { aborted++; });
    }) as any;
    await assert.rejects(
      connectionHandle(provider, fakeVault(), 25).fetch('https://api.acme.example/data', { signal: caller.signal }),
      (error: unknown) => error instanceof UpstreamTimeoutError,
    );
    assert.equal(caller.signal.aborted, false, 'the injector deadline must not abort its caller');
    assert.notEqual(upstreamSignal, caller.signal, 'the provider receives the composed signal');
    assert.equal(upstreamSignal?.aborted, true);
    assert.equal(aborted, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('ConnectionHandle caller cancellation reaches a proactive refresh token request (#209)', async () => {
  const provider = oauthProvider();
  const caller = new AbortController();
  const realFetch = globalThis.fetch;
  let tokenSignal: AbortSignal | undefined;
  let providerCalls = 0;
  let started!: () => void;
  const tokenStarted = new Promise<void>((resolve) => { started = resolve; });
  try {
    globalThis.fetch = ((url: unknown, init: RequestInit) => {
      if (String(url) === provider.tokenUrl) {
        tokenSignal = init.signal ?? undefined;
        started();
        return hangUntilAbort(tokenSignal, () => {});
      }
      providerCalls++;
      return Promise.resolve(new Response('{}', { status: 200 }));
    }) as any;
    const pending = connectionHandle(
      provider,
      fakeVault({ refreshToken: 'refresh', expiresAt: Date.now() }),
      1_000,
    ).fetch('https://api.acme.example/data', { signal: caller.signal });
    await tokenStarted;
    caller.abort(new DOMException('caller left', 'AbortError'));
    await assert.rejects(pending, (error: any) => error?.name === 'AbortError');
    assert.equal(tokenSignal?.aborted, true);
    assert.equal(providerCalls, 0, 'no provider request may run after proactive refresh cancellation');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('ConnectionHandle maps its own proactive-refresh deadline to upstream_timeout (#194)', async () => {
  const provider = oauthProvider();
  const realFetch = globalThis.fetch;
  let providerCalls = 0;
  try {
    globalThis.fetch = ((url: unknown, init: RequestInit) => {
      if (String(url) === provider.tokenUrl) {
        return hangUntilAbort(init.signal ?? undefined, () => {});
      }
      providerCalls++;
      return Promise.resolve(new Response('{}', { status: 200 }));
    }) as any;
    await assert.rejects(
      connectionHandle(
        provider,
        fakeVault({ refreshToken: 'refresh', expiresAt: Date.now() }),
        25,
      ).fetch('https://api.acme.example/data'),
      (error: unknown) => error instanceof UpstreamTimeoutError,
    );
    assert.equal(providerCalls, 0, 'a timed-out proactive refresh never reaches provider egress');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('ConnectionHandle deadline reaches a hanging 401 refresh token request (#209)', async () => {
  const provider = oauthProvider();
  const realFetch = globalThis.fetch;
  let tokenSignal: AbortSignal | undefined;
  let providerCalls = 0;
  let discarded401 = false;
  try {
    globalThis.fetch = ((url: unknown, init: RequestInit) => {
      if (String(url) === provider.tokenUrl) {
        tokenSignal = init.signal ?? undefined;
        return hangUntilAbort(tokenSignal, () => {});
      }
      providerCalls++;
      return Promise.resolve(new Response(new ReadableStream({
        cancel() { discarded401 = true; },
      }), { status: 401 }));
    }) as any;
    await assert.rejects(
      connectionHandle(
        provider,
        fakeVault({ refreshToken: 'refresh' }),
        25,
      ).fetch('https://api.acme.example/data'),
      (error: unknown) => error instanceof UpstreamTimeoutError,
    );
    assert.equal(tokenSignal?.aborted, true);
    assert.equal(providerCalls, 1, 'a timed-out refresh must not replay the provider request');
    assert.equal(discarded401, true, 'the abandoned 401 body is released');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('ConnectionHandle maps its own post-header body deadline to upstream_timeout (#194)', async () => {
  const provider = defineProvider({ ...oauthProvider(), refresh: 'none' });
  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = (async (_url: unknown, init: RequestInit) => new Response(
      new ReadableStream({
        start(controller) {
          const signal = init.signal;
          signal?.addEventListener('abort', () => controller.error(signal.reason), { once: true });
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )) as typeof fetch;
    const response = await connectionHandle(provider, fakeVault(), 25)
      .fetch('https://api.acme.example/data');
    await assert.rejects(
      () => response.text(),
      (error: unknown) => error instanceof UpstreamTimeoutError,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth callback cancellation aborts token exchange and cannot write a credential (#209)', async () => {
  const provider = oauthProvider();
  const caller = new AbortController();
  const realFetch = globalThis.fetch;
  let tokenSignal: AbortSignal | undefined;
  let writes = 0;
  let started!: () => void;
  const tokenStarted = new Promise<void>((resolve) => { started = resolve; });
  globalThis.fetch = ((_url: unknown, init: RequestInit) => {
    tokenSignal = init.signal ?? undefined;
    started();
    return hangUntilAbort(tokenSignal, () => {});
  }) as any;
  try {
    const pending = handleOAuthCallback({
      registry: new ProviderRegistry([provider]),
      consent: {
        consume: async () => ({
          status: 'active',
          row: {
            state: 'state', identity: IDENTITY, provider: provider.id, channel: 'C1',
            pkceVerifier: 'verifier', createdAt: Date.now(),
          },
        }),
      } as any,
      vault: { upsert: async () => { writes++; return true; } } as any,
      audit: quietAudit,
      redirectUri: 'https://app.example/callback',
    }, 'code', 'state', undefined, caller.signal);
    await tokenStarted;
    caller.abort(new DOMException('client disconnected', 'AbortError'));
    const result = await pending;
    assert.equal(result.ok, false);
    assert.equal(!result.ok && result.outcome, 'exchange_failed');
    assert.equal(!result.ok && result.retryable, false);
    assert.equal(tokenSignal?.aborted, true);
    assert.equal(writes, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth callback cancellation aborts its account probe and cannot write a credential (#209)', async () => {
  const provider = github({ clientId: 'client', clientSecret: 'secret' });
  const caller = new AbortController();
  const realFetch = globalThis.fetch;
  let probeSignal: AbortSignal | undefined;
  let writes = 0;
  let started!: () => void;
  const probeStarted = new Promise<void>((resolve) => { started = resolve; });
  globalThis.fetch = ((url: unknown, init: RequestInit) => {
    if (String(url) === provider.tokenUrl) {
      return Promise.resolve(new Response(JSON.stringify({ access_token: 'access' }), { status: 200 }));
    }
    probeSignal = init.signal ?? undefined;
    started();
    return hangUntilAbort(probeSignal, () => {});
  }) as any;
  try {
    const pending = handleOAuthCallback({
      registry: new ProviderRegistry([provider]),
      consent: {
        consume: async () => ({
          status: 'active',
          row: {
            state: 'state', identity: IDENTITY, provider: provider.id, channel: 'C1',
            pkceVerifier: 'verifier', createdAt: Date.now(),
          },
        }),
      } as any,
      vault: { upsert: async () => { writes++; return true; } } as any,
      audit: quietAudit,
      redirectUri: 'https://app.example/callback',
    }, 'code', 'state', undefined, caller.signal);
    await probeStarted;
    caller.abort(new DOMException('client disconnected', 'AbortError'));
    const result = await pending;
    assert.equal(result.ok, false);
    assert.equal(probeSignal?.aborted, true);
    assert.equal(writes, 0, 'a cancelled callback must not persist after its cosmetic probe');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth callback normalizes a custom accountProbe before persistence and audit (SEC-4, #209)', async () => {
  const provider = defineProvider({
    ...oauthProvider(),
    accountProbe: async () => ({ forged: true }) as any,
  });
  const identity = { enterpriseId: null, teamId: 'T1', userId: 'U1' };
  let stored: any;
  const audits: Array<{ action: string; meta: any }> = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ access_token: 'access' }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })) as any;
  try {
    const result = await handleOAuthCallback({
      registry: new ProviderRegistry([provider]),
      consent: {
        consume: async () => ({
          status: 'active',
          row: {
            state: 'state', identity, provider: provider.id, channel: 'C1',
            pkceVerifier: 'verifier', createdAt: Date.now(),
          },
        }),
        finalizeProvisioning: async (row: { createdAt: number }) => row.createdAt,
      } as any,
      vault: {
        upsertUser: async (
          _owner: unknown,
          _provider: string,
          token: unknown,
          _gate: unknown,
          afterWrite?: (tx: unknown) => Promise<void>,
        ) => {
          stored = token;
          await afterWrite?.({});
          return 'stored';
        },
      } as any,
      audit: {
        record: async (action: string, _identity: unknown, _provider: string, meta: unknown) => {
          audits.push({ action, meta });
        },
      } as any,
      redirectUri: 'https://app.example/callback',
    }, 'code', 'state');

    assert.equal(result.ok, true);
    assert.equal(result.ok && result.account, null);
    assert.equal(stored.externalAccount, null);
    assert.deepEqual(audits.find((entry) => entry.action === 'connect')?.meta, { account: null });
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('OAuth callback drops an account label containing credential material (SEC-1, #209)', async () => {
  const accessToken = 'tok_access_material_must_not_escape';
  const refreshTokenValue = 'tok_refresh_material_must_not_escape';
  const provider = defineProvider({
    ...oauthProvider(),
    accountProbe: async (token) => `account:${token}`,
  });
  let stored: any;
  const audits: Array<{ action: string; meta: unknown }> = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshTokenValue,
    scope: `read ${accessToken}`,
  }), { status: 200 })) as any;
  try {
    const result = await handleOAuthCallback({
      registry: new ProviderRegistry([provider]),
      consent: {
        consume: async () => ({
          status: 'active',
          row: {
            state: 'state-value', identity: IDENTITY, provider: provider.id, channel: 'C1',
            pkceVerifier: 'verifier-value', createdAt: Date.now(),
          },
        }),
        finalizeProvisioning: async (row: { createdAt: number }) => row.createdAt,
      } as any,
      vault: {
        upsertUser: async (
          _owner: unknown,
          _provider: string,
          token: unknown,
          _gate: unknown,
          afterWrite?: (tx: unknown) => Promise<void>,
        ) => {
          stored = token;
          await afterWrite?.({});
          return 'stored';
        },
      } as any,
      audit: {
        record: async (action: string, _identity: unknown, _provider: string, meta: unknown) => {
          audits.push({ action, meta });
        },
      } as any,
      redirectUri: 'https://app.example/callback',
    }, 'code-value', 'state-value');

    assert.equal(result.ok && result.account, null);
    assert.equal(result.ok && result.scopes, 'read');
    assert.equal(stored.externalAccount, null);
    assert.equal(stored.scopes, 'read');
    assert.deepEqual(audits.find((entry) => entry.action === 'connect')?.meta, { account: null });
    const publicValues = JSON.stringify({ result, externalAccount: stored.externalAccount, audits });
    assert.ok(!publicValues.includes(accessToken));
    assert.ok(!publicValues.includes(refreshTokenValue));
  } finally {
    globalThis.fetch = realFetch;
  }
});
