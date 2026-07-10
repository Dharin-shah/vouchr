/**
 * Fire a fire-and-forget observability/audit sink, swallowing any failure. A bad sink must never
 * affect the request it's observing. Generic over the event type so it serves the no-secret
 * `EventSink`, the raw-actor `AuditSink`, and the `CredentialHealthHook`. A missing (undefined)
 * sink is a no-op.
 *
 * Handles BOTH failure shapes: a synchronous throw (the try/catch) and an ASYNC REJECTION — the
 * hook types accept `void | Promise<void>`, and `=> void` already admitted async functions under
 * TypeScript's void-callback rule, so without the attached rejection handler a rejecting async
 * sink becomes an unhandled rejection and kills the process (Node ≥ 15 exits on those).
 */
export function safeEmit<E>(sink: ((event: E) => void | Promise<void>) | undefined, event: E): void {
  try {
    const r = sink?.(event) as unknown;
    if (r != null && typeof (r as PromiseLike<unknown>).then === 'function') {
      Promise.resolve(r).catch(() => undefined);
    }
  } catch {
    // ignore: observability is best-effort, never fatal
  }
}
