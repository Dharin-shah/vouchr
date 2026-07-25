/**
 * Make every own property of `target` non-enumerable, in place.
 *
 * SEC-1 defence for the objects Vouchr hands to host code. TypeScript's `private` is erased at
 * compile time: `private vault: Vault` is an ordinary own-ENUMERABLE property at runtime, so
 * `JSON.stringify(handle)`, `{...handle}`, `Object.entries(handle)`, `console.log(handle)` and
 * every structured logger that walks own keys serialize the whole dependency graph. That graph
 * reaches the Vault's master key, the provider's OAuth client secret, the Slack bot token and the
 * database password — and a `ConnectionHandle` / `ConnectContext` is precisely the object a host
 * is invited to hold, and the one most likely to end up in an error report, a log line, or an
 * agent tool result.
 *
 * Hiding the properties leaves `this.x` reads, `instanceof`, and method dispatch unchanged, and
 * keeps every field writable (`defineProperty` with only `enumerable` preserves the existing
 * `writable`/`configurable` — `Vault.withCredentialLocks` relies on that to set
 * `credentialLockHeld` on its transaction facade after construction).
 *
 * Call it as the LAST statement of the constructor, once every field has been assigned.
 *
 * This depends on `useDefineForClassFields: true` (pinned in tsconfig.json, and implied by
 * target ES2022): with define semantics a DECLARED-but-unassigned field such as `PgDb.refreshPool`
 * already exists as `undefined` at construction time, so it is hidden here and stays hidden when it
 * is assigned later. Flip that flag off and every such field would spring into existence enumerable
 * on first write, silently reopening it to `JSON.stringify`.
 *
 * ## What this deliberately does NOT stop
 *
 * - Properties created AFTER construction. The constructor cannot hide what does not exist yet, and
 *   a later `obj.foo = x` lands enumerable. Use {@link defineHidden} for those.
 * - Deliberate extraction: `(handle as any).vault`, `Object.getOwnPropertyNames`, or
 *   `util.inspect(handle, { showHidden: true })`. TypeScript already rejects the first, and a caller
 *   reaching for the others has decided to look inside. Note that `showHidden` is a stock inspect
 *   option, so a log formatter configured with it WILL still print the secrets — this is a guard
 *   against accidental serialization, not a confidentiality boundary against the host process.
 */
export function hideInternals(target: object): void {
  // Reflect.ownKeys, not Object.keys: covers symbol-keyed own properties too, so the invariant does
  // not quietly depend on nobody ever adding one.
  for (const key of Reflect.ownKeys(target)) {
    Object.defineProperty(target, key, { enumerable: false });
  }
}

/**
 * Assign a property without creating an own ENUMERABLE one.
 *
 * `obj.method = wrapped` shadows a prototype method with an own property that IS enumerable, which
 * puts it back into `Object.keys`, object spread and `util.inspect` output even after
 * {@link hideInternals} has already run. The Bolt adapter wraps `handle.fetch` twice to attach its
 * Slack surfaces, so without this a handle returned from `connect()` reports `["fetch"]` as its own
 * enumerable keys.
 */
export function defineHidden<T extends object>(target: T, key: keyof T & string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: false, writable: true, configurable: true });
}
