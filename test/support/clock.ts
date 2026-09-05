// Captured at load: a test that enables `t.mock.timers` replaces the global, and a reference taken
// earlier keeps running on the wall clock — which is what polling for real I/O progress needs.
const realSetTimeout = globalThis.setTimeout;

/**
 * Poll `pred` on the REAL clock until it holds. The ceiling is generous on purpose: what is awaited is
 * real work (a socket, a database read) whose duration a loaded host stretches freely, never a budget
 * the test is measuring. Usable while `t.mock.timers` is enabled — the deterministic pattern for a
 * production deadline is: send the request, `waitFor` the stage it must reach (upstream called,
 * resolver entered, first bytes relayed), then `t.mock.timers.tick(deadlineMs)` fires the timer.
 */
export async function waitFor(pred: () => boolean, timeoutMs = 15_000): Promise<void> {
  const start = performance.now();
  while (!pred()) {
    if (performance.now() - start > timeoutMs) throw new Error(`waitFor timed out after ${timeoutMs}ms: ${pred}`);
    await new Promise((r) => realSetTimeout(r, 5));
  }
}

/** Await `p` on the REAL clock; fails if it is still pending after `timeoutMs`. Pairs with a fired
 *  mock deadline: what follows the tick must be the production teardown, not some later real timer. */
export function within<T>(p: Promise<T>, timeoutMs = 15_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const ceiling = new Promise<never>((_, reject) => {
    timer = realSetTimeout(() => reject(new Error(`still pending after ${timeoutMs}ms`)), timeoutMs);
  });
  return Promise.race([p, ceiling]).finally(() => clearTimeout(timer));
}
