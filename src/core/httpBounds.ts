import { MAX_TIMER_MS } from './options';

/**
 * Small, transport-neutral HTTP resource bounds shared by OAuth token calls, account probes, and
 * credential injection. The helpers own the two easy-to-miss invariants: caller cancellation never
 * replaces Vouchr's finite deadline, and a declared Content-Length never replaces the streamed byte
 * counter.
 */

/** OAuth/token/userinfo responses are tiny. Keep malformed or hostile dependency responses bounded. */
export const OAUTH_RESPONSE_MAX_BYTES = 64 * 1024;

/** One provider-level default for token exchange/refresh, revocation, and built-in account probes. */
export const DEFAULT_OAUTH_TIMEOUT_MS = 10_000;

/** Static, no-provider-detail error used when a dependency response crosses its byte ceiling. */
export class ResponseBodyTooLargeError extends Error {
  constructor() {
    super('HTTP response body exceeds the configured limit');
    this.name = 'ResponseBodyTooLargeError';
  }
}

/** A provider request exceeded Vouchr's own bounded deadline. Caller-owned cancellation and
 * caller-owned timeout signals remain their original abort reasons instead of using this type. */
export class UpstreamTimeoutError extends Error {
  readonly code = 'upstream_timeout' as const;

  constructor() {
    super('Upstream request timed out.');
    this.name = 'UpstreamTimeoutError';
  }
}

export interface DisposableDeadline {
  signal: AbortSignal;
  /** True only when this helper's timer fired, not when the caller cancelled. */
  timedOut: () => boolean;
  /** Release the timer and caller-signal listener. Idempotent; does not abort completed work. */
  dispose: () => void;
}

// Identity, not the public DOMException name, distinguishes a Vouchr-owned deadline from a
// caller-supplied AbortSignal.timeout(). Nested internal layers can preserve that provenance.
const vouchrDeadlineReasons = new WeakSet<object>();

export function isVouchrDeadlineReason(reason: unknown): boolean {
  return typeof reason === 'object' && reason !== null && vouchrDeadlineReasons.has(reason);
}

/**
 * Compose a caller signal with one finite deadline and return explicit cleanup. `AbortSignal.any`
 * plus `AbortSignal.timeout` cannot release the timeout/listener after a fast response; this helper
 * can, which keeps high-throughput success paths from retaining deadline state until expiry.
 */
export function disposableDeadline(timeoutMs: number, caller?: AbortSignal): DisposableDeadline {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMER_MS) {
    throw new Error(`HTTP deadline must be a positive safe integer no greater than ${MAX_TIMER_MS}`);
  }

  const controller = new AbortController();
  let didTimeout = false;
  let disposed = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const release = () => {
    if (disposed) return false;
    disposed = true;
    if (timer !== undefined) clearTimeout(timer);
    caller?.removeEventListener('abort', onCallerAbort);
    return true;
  };
  const onCallerAbort = () => {
    if (!release()) return;
    controller.abort(caller?.reason);
  };

  if (caller?.aborted) {
    disposed = true;
    controller.abort(caller.reason);
  } else {
    caller?.addEventListener('abort', onCallerAbort, { once: true });
    timer = setTimeout(() => {
      if (!release()) return;
      didTimeout = true;
      const reason = new DOMException('HTTP deadline exceeded', 'TimeoutError');
      vouchrDeadlineReasons.add(reason);
      controller.abort(reason);
    }, timeoutMs);
  }

  return {
    signal: controller.signal,
    timedOut: () => didTimeout,
    dispose: () => { release(); },
  };
}

/**
 * Await an extension-point promise without letting an implementation that ignores its AbortSignal
 * pin the caller forever. The losing work is deliberately not awaited; Promise.race has already
 * attached a rejection handler, so a later failure cannot become unhandled. The abort listener is
 * removed on every path.
 */
export async function awaitWithSignal<T>(work: PromiseLike<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let onAbort!: () => void;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason ?? new DOMException('The operation was aborted', 'AbortError'));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([Promise.resolve(work), aborted]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

/** Best-effort release of an unread dependency response. Cancellation failure never masks the cause. */
export async function cancelResponseBody(response: Response | undefined): Promise<void> {
  await response?.body?.cancel().catch(() => undefined);
}

/**
 * Read one response body with both a Content-Length fast-fail and a streamed byte counter. The
 * response is cancelled on every over-cap/read-error path so the underlying connection is reusable.
 */
export async function readResponseTextCapped(response: Response, maxBytes: number): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error('HTTP response byte limit must be a positive safe integer');
  }

  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await cancelResponseBody(response);
    throw new ResponseBodyTooLargeError();
  }

  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new ResponseBodyTooLargeError();
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Parse bounded JSON without ever exposing dependency body text in an error. */
export async function readResponseJsonCapped(response: Response, maxBytes = OAUTH_RESPONSE_MAX_BYTES): Promise<unknown> {
  const text = await readResponseTextCapped(response, maxBytes);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('HTTP dependency returned invalid JSON');
  }
}

/**
 * Keep cleanup attached to a streaming Response returned to another layer. Cleanup runs when the body
 * finishes, errors, or is cancelled; a bodyless response releases immediately. This lets an injector
 * retain its deadline until its caller actually consumes the provider body without leaking the timer
 * for fast responses.
 */
export function responseWithCleanup(
  response: Response,
  cleanup: () => void,
  mapBodyError: (error: unknown) => unknown = (error) => error,
): Response {
  let cleaned = false;
  const finish = () => {
    if (cleaned) return;
    cleaned = true;
    cleanup();
  };
  if (!response.body) {
    finish();
    return response;
  }

  const reader = response.body.getReader();
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    reader.releaseLock();
  };
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const chunk = await reader.read();
        if (chunk.done) {
          release();
          finish();
          controller.close();
        } else {
          controller.enqueue(chunk.value);
        }
      } catch (error) {
        release();
        finish();
        controller.error(mapBodyError(error));
      }
    },
    async cancel(reason) {
      try {
        await reader.cancel(reason);
      } finally {
        release();
        finish();
      }
    },
  });
  const wrapped = new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  Object.defineProperty(wrapped, 'url', { value: response.url });
  return wrapped;
}
