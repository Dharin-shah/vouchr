/**
 * Fire a fire-and-forget observability/audit sink, swallowing any throw. A bad sink must never
 * affect the request it's observing. Generic over the event type so it serves both the no-secret
 * `EventSink` and the raw-actor `AuditSink`. A missing (undefined) sink is a no-op.
 */
export function safeEmit<E>(sink: ((event: E) => void) | undefined, event: E): void {
  try {
    sink?.(event);
  } catch {
    // ignore: observability is best-effort, never fatal
  }
}
