import { createHmac, timingSafeEqual, randomUUID, createHash } from 'node:crypto';

/**
 * Verified claims about WHO is acting, minted by a trusted upstream (the receiver that already
 * verified the Slack event signature) and verified by the broker. The broker resolves the vault
 * owner key ONLY from these verified claims — never from the request body — so a prompt-injected
 * caller cannot assert another human's identity and borrow their token (cross-tenant probe).
 */
export interface IdentityClaims {
  teamId: string;
  userId: string; // the acting human, from the verified Slack event upstream
  channel: string;
  threadTs?: string;
  /** Absolute expiry, epoch milliseconds (Date.now()), to match the rest of the codebase. */
  exp: number;
  /** Single-use id (replay guard within the full acceptance window). Must be non-empty. */
  jti: string;
  /**
   * Deployment-binding claims (#212), set by the minter when an {@link IdentityConfig} is used (the
   * packaged broker's path). Absent on a legacy bare-secret token. When present they are VERIFIED:
   *  - `iss` — the trusted minter (config.issuer);
   *  - `aud` — the deployment this token is for (config.audience). A token minted for deployment A is
   *    rejected by deployment B, which expects its own audience — the core cross-deployment binding.
   *  - `iat` — issued-at (epoch ms); a token issued in the future (beyond clock skew) is rejected.
   *  - `kid` — which signing key signed it, so a broker with rotated keys picks the right one and
   *    rejects an unknown key id.
   */
  iss?: string;
  aud?: string;
  iat?: number;
  kid?: string;
  /**
   * Admin authority for admin-gated routes (#54 `/v1/admin/*`). The broker cannot verify workspace
   * admin itself (no Slack client), so the trusted caller sets this AFTER its own admin check and
   * SIGNS it. The broker fails closed: an admin route with this absent/false is refused. A forged
   * request body can never assert it.
   */
  isAdmin?: boolean;
  /** Enterprise/global lifecycle mutations bind their subject into the signed assertion. An admin
   * body may repeat this value for routing, but cannot nominate a foreign user after minting. */
  offboardTargetUserId?: string;
  /**
   * Enterprise/org id (#54). When present on an admin offboard, the removal spans EVERY workspace the
   * target touches (Enterprise Grid / SCIM deprovision) via offboardUserEverywhere. Signed.
   */
  enterpriseId?: string;
  /**
   * Channel-owned credential mode (#51). Signed, so a forged request body cannot assert it — the
   * broker resolves the credential owner ONLY from this claim, never from the handle. Absent → 'user'
   * (the historical default; channel modes are strictly opt-in on the broker via `channelConfig`).
   */
  ownerKind?: 'user' | 'channel';
  /**
   * The caller's channelIneligibleReason() === null verdict, signed (#51). The broker has no Slack
   * client, so the trusted caller computes eligibility (externally-shared / Slack-Connect / DM /
   * archived refuse a shared cred) and signs the result. The broker fails CLOSED: a channel-owned
   * request with this absent/false is refused.
   */
  channelEligible?: boolean;
  /**
   * The delivery channel's Slack conversation TYPE — the event `channel_type` ('im'/'mpim' for a
   * DM/group-DM). Signed by the trusted caller (it verified the Slack event), so the broker can
   * classify the mutable-GOVERNANCE scope (governanceChannelOf) exactly like Bolt does, instead of
   * guessing from the id: an MPIM 'G…' id is indistinguishable from a private channel without it.
   * Absent → the broker falls back to the id heuristic (a 1:1 DM 'D…' is still exempt; a group DM
   * with no type stays governed). Static Policy always evaluates against the raw `channel`, so this
   * only widens/narrows the admin-mutable allowlist scope, never the deployment policy.
   */
  channelType?: string;
}

/** Hard ceiling on a token's lifetime: a verified token is rejected if exp is further out than this. */
export const MAX_LIFETIME_MS = 5 * 60 * 1000;

/** Clock-skew tolerance for iat/exp comparisons in deployment-bound (config) mode. Small + documented. */
export const IDENTITY_SKEW_MS = 30 * 1000;

/** Minimum identity signing-secret strength: at least 32 bytes of key material (#212). */
export const MIN_IDENTITY_SECRET_BYTES = 32;

/** Bound deployment labels and replay keys before they reach signed payloads or persistent storage. */
const MAX_IDENTITY_LABEL_BYTES = 256;
const MAX_IDENTITY_SECRET_BYTES = 1024;
const MAX_JTI_BYTES = 128;

/**
 * A named identity signing key. `kid` is a short, stable fingerprint of the secret ({@link identityKid}),
 * so the minter and every broker replica derive the SAME id from the SAME secret with no extra config —
 * and a broker mid-rotation can tell which key signed a token and reject an unknown one.
 */
export interface IdentityKey {
  readonly kid: string;
  readonly secret: string;
}

/**
 * Deployment-bound identity configuration (#212) — the hardened alternative to a bare secret. Binds
 * every assertion to ONE deployment (`audience`) and one `issuer`, signs with the active key
 * (`keys[0]`), and verifies against ANY key in `keys` (active + previous, for rolling rotation with no
 * downtime). Passing this to {@link mintIdentity}/{@link verifyIdentity} instead of a `string` turns on
 * issuer/audience/kid/iat verification; a bare `secret: string` stays legacy single-deployment mode.
 */
export interface IdentityConfig {
  readonly issuer: string;
  /** The deployment id. A token minted for one audience is rejected by a broker expecting another. */
  readonly audience: string;
  /** keys[0] signs new tokens; every key is a verify candidate (rotation overlap). Non-empty. */
  readonly keys: readonly IdentityKey[];
}

/** A validated deployment-bound snapshot, deep-frozen at runtime. */
export type NormalizedIdentityConfig = IdentityConfig;

/** Module-private brand: only snapshots produced by the validator get the normalize-once fast path. */
const NORMALIZED_IDENTITY_CONFIGS = new WeakSet<object>();

/** A short, deterministic key id from the secret — same secret ⇒ same kid on minter and every broker. */
export function identityKid(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 12);
}

/** Obvious placeholder secrets rejected regardless of length — the "example" case of #212. */
const PLACEHOLDER_SECRETS = new Set([
  'secret', 'changeme', 'change-me', 'password', 'test', 'example', 'shhh', 'vouchr', 'identity',
  'broker-secret', 'placeholder', 'your-secret-here', 'replace-me',
]);
const PLACEHOLDER_AUDIENCES = new Set([
  'replace_me-vouchr-production', 'replace-me', 'changeme', 'your-deployment-id',
]);

const IDENTITY_CONFIG_FIELDS = new Set<PropertyKey>(['issuer', 'audience', 'keys']);
const IDENTITY_KEY_FIELDS = new Set<PropertyKey>(['kid', 'secret']);

function isPlainRecord(value: unknown): value is Record<PropertyKey, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactFields(
  value: Record<PropertyKey, unknown>,
  allowed: ReadonlySet<PropertyKey>,
  required: readonly PropertyKey[],
  label: string,
): void {
  if (Reflect.ownKeys(value).some((field) => !allowed.has(field))) {
    throw new Error(`${label} contains an unknown field`);
  }
  for (const field of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !('value' in descriptor)) throw new Error(`${label} fields must be plain data values`);
  }
  if (required.some((field) => !Object.hasOwn(value, field))) throw new Error(`${label} is missing a required field`);
}

function hasControlCharacters(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function assertBoundedLabel(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    Buffer.byteLength(value, 'utf8') > MAX_IDENTITY_LABEL_BYTES ||
    hasControlCharacters(value)
  ) {
    throw new Error(`${label} must be a non-empty, bounded identifier without surrounding whitespace or control characters`);
  }
}

/** Reject only deterministic repeated patterns; this is not a claim to estimate arbitrary entropy. */
function hasObviousRepeatedPattern(value: string): boolean {
  const maxUnit = Math.min(16, Math.floor(value.length / 2));
  for (let unitLength = 1; unitLength <= maxUnit; unitLength++) {
    if (value.length % unitLength !== 0) continue;
    const unit = value.slice(0, unitLength);
    if (unit.repeat(value.length / unitLength) === value) return true;
  }
  return false;
}

function assertStrongIdentitySecretFor(secret: unknown, label: string): asserts secret is string {
  if (typeof secret === 'string' && PLACEHOLDER_SECRETS.has(secret.trim().toLowerCase())) {
    throw new Error(`${label} is a known placeholder value; use random key material`);
  }
  if (
    typeof secret !== 'string' ||
    !secret.trim() ||
    Buffer.byteLength(secret, 'utf8') < MIN_IDENTITY_SECRET_BYTES ||
    Buffer.byteLength(secret, 'utf8') > MAX_IDENTITY_SECRET_BYTES
  ) {
    throw new Error(
      `${label} must be at least ${MIN_IDENTITY_SECRET_BYTES} bytes and at most ${MAX_IDENTITY_SECRET_BYTES} bytes of random key material`,
    );
  }
  if (hasObviousRepeatedPattern(secret)) {
    throw new Error(`${label} has an obvious repeated pattern; use random key material`);
  }
}

/**
 * Reject an identity signing secret that is too short or an obvious placeholder (#212). The signing
 * secret is the broker's trust root, so a weak one lets anyone mint accepted assertions. Enforced at
 * the env/config boundary ({@link loadIdentityConfig}), mirroring how master-key strength is validated
 * in `loadKeyring` — the low-level sign/verify helpers trust their caller, like the vault trusts its key.
 */
export function assertStrongIdentitySecret(secret: string): void {
  assertStrongIdentitySecretFor(secret, 'identity secret');
}

/**
 * The one runtime boundary for programmatic and env-built identity configuration (#212). Rejects
 * malformed/ambiguous objects and weak or mis-labelled rotation keys before any token is minted or
 * verified. The returned clone is deep-frozen so later caller mutation cannot change a live broker's
 * trust root.
 */
export function normalizeIdentityConfig(config: IdentityConfig): NormalizedIdentityConfig {
  if (config && typeof config === 'object' && NORMALIZED_IDENTITY_CONFIGS.has(config)) {
    return config as NormalizedIdentityConfig;
  }
  if (!isPlainRecord(config)) throw new Error('identity config must be a plain object');
  assertExactFields(config, IDENTITY_CONFIG_FIELDS, ['issuer', 'audience', 'keys'], 'identity config');
  assertBoundedLabel(config.issuer, 'identity config issuer');
  assertBoundedLabel(config.audience, 'identity config audience');
  if (PLACEHOLDER_AUDIENCES.has(config.audience.toLowerCase())) {
    throw new Error('identity config audience is a placeholder; set one stable deployment id');
  }

  const rawKeys = config.keys;
  if (!Array.isArray(rawKeys) || rawKeys.length < 1 || rawKeys.length > 2) {
    throw new Error('identity config keys must contain one active key and at most one previous key');
  }
  const keyIndexes = Array.from({ length: rawKeys.length }, (_, index) => index);
  const allowedKeyIndexes = new Set<PropertyKey>(['length', ...keyIndexes.map(String)]);
  if (
    keyIndexes.some((index) => !Object.hasOwn(rawKeys, index)) ||
    Reflect.ownKeys(rawKeys).some((field) => !allowedKeyIndexes.has(field))
  ) {
    throw new Error('identity config keys must be a dense array without extra fields');
  }

  const kids = new Set<string>();
  const secretBytes: Buffer[] = [];
  const keys = rawKeys.map((rawKey, index): IdentityKey => {
    if (!isPlainRecord(rawKey)) throw new Error(`identity config key ${index + 1} must be a plain object`);
    assertExactFields(rawKey, IDENTITY_KEY_FIELDS, ['kid', 'secret'], `identity config key ${index + 1}`);
    assertStrongIdentitySecretFor(rawKey.secret, `identity config key ${index + 1} secret`);
    const expectedKid = identityKid(rawKey.secret);
    if (rawKey.kid !== expectedKid) {
      throw new Error(`identity config key ${index + 1} kid must be the canonical fingerprint of its secret`);
    }
    const bytes = Buffer.from(rawKey.secret, 'utf8');
    if (kids.has(expectedKid) || secretBytes.some((other) => other.length === bytes.length && timingSafeEqual(other, bytes))) {
      throw new Error('identity config active and previous keys must be distinct');
    }
    kids.add(expectedKid);
    secretBytes.push(bytes);
    return Object.freeze({ kid: expectedKid, secret: rawKey.secret });
  });

  const normalized = Object.freeze({
    issuer: config.issuer,
    audience: config.audience,
    keys: Object.freeze(keys),
  });
  NORMALIZED_IDENTITY_CONFIGS.add(normalized);
  return normalized;
}

type SecretMaterial = string | Buffer;

function secretBuffer(material: SecretMaterial): Buffer {
  return Buffer.isBuffer(material) ? Buffer.from(material) : Buffer.from(material, 'utf8');
}

function addRawAndDecodedMasterKey(materials: Buffer[], raw: string | undefined): void {
  if (!raw) return;
  const value = raw.trim();
  if (!value) return;
  materials.push(Buffer.from(raw, 'utf8'));
  if (value !== raw) materials.push(Buffer.from(value, 'utf8'));
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length) materials.push(decoded);
}

function configuredOtherSecretBytes(env: NodeJS.ProcessEnv, explicit: readonly SecretMaterial[]): Buffer[] {
  if (!Array.isArray(explicit) || explicit.some((value) => typeof value !== 'string' && !Buffer.isBuffer(value))) {
    throw new Error('other secret material must contain only strings or buffers');
  }
  const materials = explicit.map(secretBuffer);
  for (const [name, value] of Object.entries(env)) {
    if (
      value &&
      (name === 'SLACK_SIGNING_SECRET' || name === 'VOUCHR_BROKER_TOKEN' || name.endsWith('_CLIENT_SECRET'))
    ) {
      materials.push(Buffer.from(value, 'utf8'));
    }
  }
  addRawAndDecodedMasterKey(materials, env.VOUCHR_MASTER_KEY);
  for (const entry of (env.VOUCHR_MASTER_KEYS ?? '').split(',')) {
    const colon = entry.indexOf(':');
    if (colon >= 0) addRawAndDecodedMasterKey(materials, entry.slice(colon + 1));
  }
  return materials;
}

/**
 * Enforce purpose separation at every construction boundary that can see another configured secret.
 * The comparison is byte-wise and errors are deliberately static so neither value can reach output.
 */
export function assertIdentityPurposeDistinct(
  config: IdentityConfig,
  otherSecrets: readonly SecretMaterial[],
  conflictsWithHiddenSecret: (secret: string) => boolean = () => false,
): void {
  const normalized = normalizeIdentityConfig(config);
  if (!Array.isArray(otherSecrets) || otherSecrets.some((value) => typeof value !== 'string' && !Buffer.isBuffer(value))) {
    throw new Error('other secret material must contain only strings or buffers');
  }
  const otherBytes = otherSecrets.map(secretBuffer);
  for (const identityKey of normalized.keys) {
    const identityBytes = Buffer.from(identityKey.secret, 'utf8');
    if (
      otherBytes.some((other) => other.length === identityBytes.length && timingSafeEqual(other, identityBytes)) ||
      conflictsWithHiddenSecret(identityKey.secret)
    ) {
      throw new Error(
        'identity signing keys must be distinct from the master key, broker token, provider client secrets, and Slack signing secret',
      );
    }
  }
}

/**
 * Build a deployment-bound {@link IdentityConfig} from env (#212), the packaged broker's identity
 * setup — the parallel to `loadKeyring` for the master key. Fails closed on a missing/weak secret,
 * a missing deployment id, or a previous key equal to the active one. `otherSecrets` (the master
 * key(s), broker token) are checked for equality so one value can't be reused across purposes.
 *  - VOUCHR_IDENTITY_SECRET          — active signing secret (required, >= 32 bytes).
 *  - VOUCHR_IDENTITY_SECRET_PREVIOUS — previous secret during a rotation window (optional).
 *  - VOUCHR_DEPLOYMENT_ID            — the audience every assertion is bound to (required).
 *  - VOUCHR_IDENTITY_ISSUER          — the issuer claim (optional; default 'vouchr').
 */
export function loadIdentityConfig(
  env: NodeJS.ProcessEnv,
  otherSecrets: readonly SecretMaterial[] = [],
): NormalizedIdentityConfig {
  const active = env.VOUCHR_IDENTITY_SECRET;
  if (!active || !active.trim()) {
    throw new Error('VOUCHR_IDENTITY_SECRET is required (the HS256 secret shared with the identity-token minter)');
  }
  const audience = env.VOUCHR_DEPLOYMENT_ID;
  if (!audience || !audience.trim()) {
    throw new Error('VOUCHR_DEPLOYMENT_ID is required (the deployment id every identity assertion is bound to)');
  }
  assertStrongIdentitySecretFor(active, 'VOUCHR_IDENTITY_SECRET');
  const keys: IdentityKey[] = [{ kid: identityKid(active), secret: active }];
  const previous = env.VOUCHR_IDENTITY_SECRET_PREVIOUS;
  if (previous !== undefined) {
    if (!previous.trim()) throw new Error('VOUCHR_IDENTITY_SECRET_PREVIOUS must not be empty when set');
    assertStrongIdentitySecretFor(previous, 'VOUCHR_IDENTITY_SECRET_PREVIOUS');
    if (previous === active) throw new Error('VOUCHR_IDENTITY_SECRET_PREVIOUS must differ from VOUCHR_IDENTITY_SECRET');
    keys.push({ kid: identityKid(previous), secret: previous });
  }
  const issuer = env.VOUCHR_IDENTITY_ISSUER ?? 'vouchr';
  const normalized = normalizeIdentityConfig({
    issuer,
    audience,
    keys,
  });

  // Reused-purpose guard (#212): compare the actual HMAC key bytes with every colocated secret and
  // both the raw and decoded master-key forms. Values never reach an error or log message.
  assertIdentityPurposeDistinct(normalized, configuredOtherSecretBytes(env, otherSecrets));
  return normalized;
}

/** Raised on any verification failure. Carries no token/secret material; the broker maps it to 401. */
export class IdentityError extends Error {
  constructor(reason: string) {
    super(`identity rejected: ${reason}`);
    this.name = 'IdentityError';
  }
}

const b64url = (s: string | Buffer): string => Buffer.from(s).toString('base64url');

/**
 * HS256 over the payload. Format is `base64url(json).base64url(hmac)` — deliberately NOT a full JWT:
 * there is no `alg` header to read from the token, so an algorithm-substitution attack has no surface.
 * Minter-side helper; the minter is responsible for setting `exp <= now + 5min` and a unique `jti`.
 */
export function signIdentity(claims: IdentityClaims, secret: string): string {
  const payload = b64url(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

/** The acting-human fields a caller supplies per request; the minter fills `jti` and `exp` safely.
 *  The admin/lifecycle (#54) and channel-fact (#51) fields are optional and default to a non-admin,
 *  single-workspace, user-owned request when omitted. */
export type MintIdentityInput = Pick<
  IdentityClaims,
  | 'teamId'
  | 'userId'
  | 'channel'
  | 'threadTs'
  | 'isAdmin'
  | 'offboardTargetUserId'
  | 'enterpriseId'
  | 'ownerKind'
  | 'channelEligible'
  | 'channelType'
>;

/**
 * Mint a short-lived, single-use identity token for ONE broker call — the safe wrapper around
 * `signIdentity`. It fills the two fields that are easy to get wrong:
 *   - a fresh random `jti` (reuse it and the broker rejects the second call as a replay), and
 *   - `exp = now + ttlMs`, clamped to the 5-minute ceiling the broker enforces.
 *
 * Call it on the CALLER side — the agent/runtime that already authenticated the acting human — then
 * send the returned string as `identityToken` in the /v1/fetch body. The signing secret is the
 * broker's trust root: keep it only in the minter and the broker, never in the model or the agent's
 * tool surface. Mint per request; do not cache or reuse a token across calls.
 */
export function mintIdentity(input: MintIdentityInput, key: string | IdentityConfig, ttlMs = 60_000, now = Date.now()): string {
  const config = typeof key === 'string' ? null : normalizeIdentityConfig(key);
  if (config && (!Number.isSafeInteger(now) || !Number.isSafeInteger(ttlMs))) {
    throw new Error('identity token now and ttlMs must be finite safe integers');
  }
  const lifetime = Math.min(Math.max(1, ttlMs), MAX_LIFETIME_MS);
  if (config && !Number.isSafeInteger(now + lifetime)) {
    throw new Error('identity token expiry must be a finite safe integer');
  }
  const claims: IdentityClaims = {
    teamId: input.teamId,
    userId: input.userId,
    channel: input.channel,
    ...(input.threadTs !== undefined ? { threadTs: input.threadTs } : {}),
    ...(input.isAdmin !== undefined ? { isAdmin: input.isAdmin } : {}),
    ...(input.offboardTargetUserId !== undefined
      ? { offboardTargetUserId: input.offboardTargetUserId }
      : {}),
    ...(input.enterpriseId !== undefined ? { enterpriseId: input.enterpriseId } : {}),
    ...(input.ownerKind !== undefined ? { ownerKind: input.ownerKind } : {}),
    ...(input.channelEligible !== undefined ? { channelEligible: input.channelEligible } : {}),
    ...(input.channelType !== undefined ? { channelType: input.channelType } : {}),
    jti: randomUUID(),
    exp: now + lifetime,
  };
  // Bare secret → legacy single-deployment token (no binding). IdentityConfig → deployment-bound:
  // stamp iss/aud/iat/kid and sign with the ACTIVE key, so the broker can verify the binding + pick
  // the key by kid during rotation.
  if (!config) return signIdentity(claims, key as string);
  const active = config.keys[0];
  const bound: IdentityClaims = { ...claims, iss: config.issuer, aud: config.audience, iat: now, kid: active.kid };
  return signIdentity(bound, active.secret);
}

/**
 * Low-level in-memory replay guard for direct verifier unit tests. It is never accepted by the
 * production broker: a fleet could otherwise accept one jti once per pod.
 */
export class ReplayGuard {
  private seen = new Map<string, number>(); // jti -> exp (epoch ms)
  private lastPrune = 0;

  /** Returns true if this jti is fresh (and records it); false if it was already used. */
  use(jti: string, exp: number, now = Date.now()): boolean {
    // ponytail: prune cadence 60s — the check+insert below run every call (correctness), only the
    // O(n) sweep is throttled, mirroring DbReplayStore. Between prunes an expired jti lingers in the
    // map, but verifyIdentity rejects an expired token before the replay check so it's never accepted;
    // memory is bounded by ~60s of traffic on top of the live (<=5min) window.
    if (now - this.lastPrune > 60_000) {
      this.lastPrune = now;
      for (const [j, e] of this.seen) if (e <= now) this.seen.delete(j);
    }
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, exp);
    return true;
  }
}

function isClaims(v: unknown): v is IdentityClaims {
  if (!v || typeof v !== 'object') return false;
  const c = v as Record<string, unknown>;
  return (
    typeof c.teamId === 'string' &&
    typeof c.userId === 'string' &&
    typeof c.channel === 'string' &&
    typeof c.exp === 'number' &&
    // jti is the replay key; an empty one is not a usable single-use id — reject it (#212), never coerce.
    typeof c.jti === 'string' && c.jti.length > 0 &&
    (c.threadTs === undefined || typeof c.threadTs === 'string') &&
    // Deployment-binding claims (#212): reject a wrong-typed value rather than coercing it — a
    // malformed signed iss/aud/iat/kid fails closed instead of silently disabling a binding check.
    (c.iss === undefined || typeof c.iss === 'string') &&
    (c.aud === undefined || typeof c.aud === 'string') &&
    (c.iat === undefined || typeof c.iat === 'number') &&
    (c.kid === undefined || typeof c.kid === 'string') &&
    // Admin/lifecycle claims (#54): reject a wrong-typed value rather than coercing — a malformed
    // signed isAdmin fails closed (it can't slip through as true).
    (c.isAdmin === undefined || typeof c.isAdmin === 'boolean') &&
    (c.offboardTargetUserId === undefined || typeof c.offboardTargetUserId === 'string') &&
    (c.enterpriseId === undefined || typeof c.enterpriseId === 'string') &&
    // Channel-fact claims (#51): reject a wrong-typed value rather than coercing it — a malformed
    // signed claim fails closed (an unknown ownerKind can't slip through as 'channel').
    (c.ownerKind === undefined || c.ownerKind === 'user' || c.ownerKind === 'channel') &&
    (c.channelEligible === undefined || typeof c.channelEligible === 'boolean') &&
    // Signed conversation type: reject a wrong-typed value rather than coercing it. Only 'im'/'mpim'
    // affect governance (governanceChannelOf); any other bounded string is treated as a governed channel.
    (c.channelType === undefined || typeof c.channelType === 'string')
  );
}

function isBoundedJti(jti: string): boolean {
  return (
    jti.length > 0 &&
    jti === jti.trim() &&
    Buffer.byteLength(jti, 'utf8') <= MAX_JTI_BYTES &&
    !hasControlCharacters(jti)
  );
}

/**
 * Verify a minted identity token. Throws IdentityError on a bad/missing signature, a malformed or
 * incomplete payload, an expired token, an over-long lifetime (> 5min), or a replayed jti. On
 * success returns the verified claims; the broker builds the owner key from these and nothing else.
 */
export function verifyIdentity(
  token: string,
  key: string | IdentityConfig,
  opts: { replay?: ReplayGuard; now?: number } = {},
): IdentityClaims {
  const now = opts.now ?? Date.now();
  if (!Number.isSafeInteger(now)) throw new IdentityError('invalid verification time');
  const config = typeof key === 'string' ? null : normalizeIdentityConfig(key);
  if (typeof token !== 'string' || !token) throw new IdentityError('missing token');
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) throw new IdentityError('malformed');
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);

  // Parse the payload up front. In config mode the `kid` selects the verifying key, so it must be read
  // before the signature check — safe, because nothing here is trusted until the HMAC verifies below:
  // a forged kid either names no key (rejected) or names a real key whose secret won't match the sig.
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    throw new IdentityError('malformed payload');
  }
  if (!isClaims(parsed)) throw new IdentityError('incomplete claims');
  const claims = parsed;

  // Select the verifying secret. Bare string → legacy single key. IdentityConfig → the key whose kid
  // matches the token's `kid`; an unknown kid is rejected before any signature work (#212).
  let secret: string;
  if (!config) {
    secret = key as string;
  } else {
    const match = claims.kid ? config.keys.find((k) => k.kid === claims.kid) : undefined;
    if (!match) throw new IdentityError('unknown kid');
    secret = match.secret;
  }

  const expected = createHmac('sha256', secret).update(payload).digest('base64url');
  // Constant-time compare; differing lengths can't be timingSafeEqual'd, so reject first.
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new IdentityError('bad signature');

  // One documented tolerance for every deployment. A per-replica skew knob would create another
  // compatibility state and is unnecessary for the supported production shape.
  const skew = config ? IDENTITY_SKEW_MS : 0;
  if (!config) {
    // Legacy mode: exactly the historical time checks (no iss/aud/iat/skew).
    if (claims.exp <= now) throw new IdentityError('expired');
    if (claims.exp - now > MAX_LIFETIME_MS) throw new IdentityError('lifetime exceeds 5min');
  } else {
    // Deployment-bound mode (#212): a token minted for another deployment (aud) or minter (iss), or
    // issued in the future / with an over-long lifetime, fails BEFORE the replay check (and authz).
    if (claims.iss !== config.issuer) throw new IdentityError('wrong issuer');
    if (claims.aud !== config.audience) throw new IdentityError('wrong audience');
    const iat = claims.iat;
    if (typeof iat !== 'number' || !Number.isSafeInteger(iat)) throw new IdentityError('invalid iat');
    if (!Number.isSafeInteger(claims.exp)) throw new IdentityError('invalid exp');
    if (!isBoundedJti(claims.jti)) throw new IdentityError('invalid jti');
    if (iat > now + skew) throw new IdentityError('issued in the future');
    if (claims.exp <= now - skew) throw new IdentityError('expired');
    if (claims.exp <= iat) throw new IdentityError('expiry must follow issued-at');
    if (claims.exp - iat > MAX_LIFETIME_MS) throw new IdentityError('lifetime exceeds 5min');
  }
  // Record the jti until the acceptance HORIZON (exp + skew), not exp: a token is acceptable in
  // [exp, exp+skew) under clock skew, so the replay record must live that long or a pruned jti could be
  // replayed there (#212). Legacy mode has skew 0, so the horizon is exp — unchanged.
  if (opts.replay && !opts.replay.use(claims.jti, claims.exp + skew, now)) throw new IdentityError('replayed jti');

  return claims;
}
