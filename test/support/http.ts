import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { relative } from 'node:path';
import type { TestContext } from 'node:test';
import { within } from './clock';

const CLOSE_TIMEOUT_MS = 5_000;

/**
 * Listen on an ephemeral loopback port and own the teardown (#332).
 *
 * Bind 127.0.0.1 explicitly: a bare `listen(0)` takes the dual-stack wildcard `*:PORT`, and macOS may
 * give another process that same PORT on the more specific `127.0.0.1:PORT` (seen: an MDM agent's
 * loopback listener). That listener then captures every test request to the port and never answers —
 * the observed "0% CPU, one loopback socket open" stall. A 127.0.0.1 bind cannot be shadowed that way.
 *
 * Teardown destroys every connection first (a pooled keep-alive client socket otherwise holds `close()`,
 * and so process exit, open) and bounds the close, so a stall fails the test naming the file instead of
 * hanging the run. Tolerates a test's own earlier fire-and-forget `server.close()`.
 */
export async function listen(t: TestContext, server: Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => closeServer(server, `${relative(process.cwd(), t.filePath ?? '?')} › ${t.name}`));
  return (server.address() as AddressInfo).port;
}

/** Destroy every connection, then await close under a bound. For servers not started via `listen`. */
export async function closeServer(server: Server, label: string): Promise<void> {
  server.closeAllConnections();
  if (!server.listening) return; // the test already closed it; the sockets just destroyed were all that could block
  await within(new Promise<void>((r) => server.close(() => r())), CLOSE_TIMEOUT_MS).catch(() => {
    throw new Error(`${label}: server.close() still pending after ${CLOSE_TIMEOUT_MS}ms (#332)`);
  });
}
