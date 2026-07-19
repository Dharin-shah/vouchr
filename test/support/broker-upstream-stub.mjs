// Two-process analog of the suite's in-process `withFetch` stub (TEST-3): the spawned packaged
// broker must perform no real network egress inside `npm test`. Loaded into the broker child via
// `--import`; ONLY the fake provider upstream host is intercepted — PostgreSQL and the loopback
// HTTP between the test process and the broker stay real. The stubbed response is synthetic and
// secret-free; anything else egressing from the child fails exactly as it would offline.
globalThis.fetch = async (input) => {
  const url = new URL(typeof input === 'string' ? input : input.url);
  if (url.hostname === 'api.bridge.test') {
    return new Response(JSON.stringify({ ok: true, path: url.pathname }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  throw new Error('unexpected external egress from broker test child');
};
