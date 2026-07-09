import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  encrypt,
  decrypt,
  seal,
  open,
  loadKeyring,
  toKeyring,
  tryDecryptDirect,
  type EnvelopeProvider,
  type Keyring,
} from '../src/core/crypto';

// Master-key rotation for the DIRECT (non-KMS) path (#115). The discrimination tests here are
// written against ciphertexts minted by the CURRENT code path (encrypt/seal with a bare Buffer,
// which is byte-for-byte today's scheme-0 format) so a regression that bricks existing rows fails
// loudly. No committed binary fixtures: every blob is generated in-test.

const OLD = randomBytes(32); // the pre-rotation master key (today's VOUCHR_MASTER_KEY)
const NEW = randomBytes(32); // the rotated-in primary
const b64 = (k: Buffer) => k.toString('base64');

/** Keyring literal helper for tests that don't go through env parsing. */
function ring(primary: { id: string | null; key: Buffer }, rest: { id: string; key: Buffer }[] = [], idless?: Buffer): Keyring {
  const listed = primary.id === null ? rest : [{ id: primary.id, key: primary.key }, ...rest];
  const idlessKey = primary.id === null ? primary.key : idless;
  return {
    primary,
    byId: new Map(listed.map((e) => [e.id, e.key])),
    legacy: [...(idlessKey ? [{ id: null as string | null, key: idlessKey }] : []), ...listed],
  };
}

// ---------------------------------------------------------------------------------------------
// loadKeyring: env parsing + validation (SEC-4: ids are constrained BEFORE they can reach errors,
// ciphertext headers, or rekey output).
// ---------------------------------------------------------------------------------------------

test('loadKeyring: VOUCHR_MASTER_KEY alone is the sole, id-less key (back-compat)', () => {
  const r = loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD) });
  assert.equal(r.primary.id, null);
  assert.ok(r.primary.key.equals(OLD));
  assert.equal(r.byId.size, 0);
  assert.equal(r.legacy.length, 1);
});

test('loadKeyring: VOUCHR_MASTER_KEYS first entry is the primary; all entries decrypt', () => {
  const r = loadKeyring({ VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)}, k2019:${b64(OLD)}` });
  assert.equal(r.primary.id, 'k2025');
  assert.ok(r.primary.key.equals(NEW));
  assert.ok(r.byId.get('k2019')?.equals(OLD));
  assert.ok(r.byId.get('k2025')?.equals(NEW));
});

test('loadKeyring: VOUCHR_MASTER_KEY and VOUCHR_MASTER_KEYS may coexist; KEYS wins for writes', () => {
  const r = loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD), VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)}` });
  assert.equal(r.primary.id, 'k2025');
  // the id-less key stays a scheme-0 decryption candidate
  assert.ok(r.legacy.some((e) => e.id === null && e.key.equals(OLD)));
});

test('loadKeyring: neither env set → actionable error naming VOUCHR_MASTER_KEY', () => {
  assert.throws(() => loadKeyring({}), /VOUCHR_MASTER_KEY/);
});

test('loadKeyring: rejects a key that is not 32 bytes, naming the entry but never the material', () => {
  assert.throws(() => loadKeyring({ VOUCHR_MASTER_KEY: 'dG9vc2hvcnQ=' }), /32 bytes/);
  assert.throws(() => loadKeyring({ VOUCHR_MASTER_KEYS: `a:dG9vc2hvcnQ=` }), /32 bytes/);
});

test('loadKeyring: rejects invalid key ids WITHOUT echoing the entry (a swapped id:key must not leak)', () => {
  // Swapped "key:id" — the would-be id is actual key material; the error must not contain it.
  const swapped = `${b64(OLD)}:k2019`;
  assert.throws(
    () => loadKeyring({ VOUCHR_MASTER_KEYS: swapped }),
    (e: Error) => {
      assert.ok(!e.message.includes(b64(OLD)), 'error must not echo key material');
      assert.match(e.message, /key id/i);
      return true;
    },
  );
  // Charset violations and over-length ids are rejected up front.
  assert.throws(() => loadKeyring({ VOUCHR_MASTER_KEYS: `bad id!:${b64(NEW)}` }), /key id/i);
  assert.throws(() => loadKeyring({ VOUCHR_MASTER_KEYS: `${'x'.repeat(33)}:${b64(NEW)}` }), /key id/i);
  // Missing id entirely.
  assert.throws(() => loadKeyring({ VOUCHR_MASTER_KEYS: b64(NEW) }), /id:base64key|key id/i);
});

test('loadKeyring: rejects duplicate key ids', () => {
  assert.throws(() => loadKeyring({ VOUCHR_MASTER_KEYS: `a:${b64(NEW)},a:${b64(OLD)}` }), /'a' twice|duplicate/i);
});

// ---------------------------------------------------------------------------------------------
// Scheme discrimination — the part that can brick existing rows. Legacy blobs below are produced
// by the CURRENT Buffer code path.
// ---------------------------------------------------------------------------------------------

test('bit-for-bit legacy: Buffer and id-less keyring writes are the same scheme-0 layout', () => {
  const viaBuffer = encrypt('tok', OLD);
  assert.equal(viaBuffer.length, 12 + 16 + 3, 'iv|tag|ct with NO scheme byte');
  const r0 = loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD) });
  const viaRing = encrypt('tok', r0);
  assert.equal(viaRing.length, viaBuffer.length);
  // cross-readable in both directions: old reader ↔ new writer, new reader ↔ old writer
  assert.equal(decrypt(viaRing, OLD), 'tok');
  assert.equal(decrypt(viaBuffer, r0), 'tok');
});

test('scheme-0 row written by old code decrypts via the id-less key', () => {
  const legacy = encrypt('tok_old', OLD);
  const r = loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD), VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)}` });
  assert.equal(decrypt(legacy, r), 'tok_old');
});

test('scheme-0 row decrypts when the old key was MOVED into VOUCHR_MASTER_KEYS under an id', () => {
  // Acceptance: VOUCHR_MASTER_KEYS=new:...,old:... alone (no id-less key) still reads old rows.
  const legacy = encrypt('tok_old', OLD);
  const r = loadKeyring({ VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)},k2019:${b64(OLD)}` });
  assert.equal(decrypt(legacy, r), 'tok_old');
});

test('scheme-0 row is unreadable once the writing key is dropped from the ring (fail closed)', () => {
  const legacy = encrypt('tok_old', OLD);
  const r = loadKeyring({ VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)}` });
  assert.throws(() => decrypt(legacy, r));
});

test('scheme-2 (keyed) round-trip: leading 0x02, embeds the key id, never the material or plaintext', () => {
  const r = loadKeyring({ VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)},k2019:${b64(OLD)}` });
  const blob = encrypt('tok_new', r);
  assert.equal(blob[0], 0x02, 'keyed rows begin with the 0x02 scheme byte');
  assert.equal(blob[1], 'k2025'.length);
  assert.equal(blob.subarray(2, 2 + blob[1]).toString('utf8'), 'k2025');
  assert.ok(!blob.toString('latin1').includes('tok_new'), 'ciphertext must not contain the plaintext');
  assert.ok(!blob.includes(NEW.subarray(0, 8)), 'ciphertext must not contain key material');
  assert.equal(decrypt(blob, r), 'tok_new');
});

test('keyed row routes by EXACT id: same key bytes under a different id must not decrypt (no try-all)', () => {
  const writer = ring({ id: 'k2025', key: NEW });
  const blob = encrypt('tok', writer);
  // Reader has the SAME key material but registered under a different id → unknown id, hard fail.
  const reader = ring({ id: 'other', key: NEW });
  assert.throws(
    () => decrypt(blob, reader),
    (e: Error) => {
      assert.match(e.message, /k2025/, 'error must name the unknown key id');
      assert.match(e.message, /VOUCHR_MASTER_KEYS/, 'error must say how to fix it');
      assert.ok(!e.message.includes(b64(NEW)), 'error must not leak key material');
      return true;
    },
  );
});

test('keyed row with a known id but tampered ciphertext fails GCM auth (never wrong plaintext)', () => {
  const r = ring({ id: 'k2025', key: NEW });
  const blob = encrypt('tok', r);
  blob[blob.length - 1] ^= 0x01;
  assert.throws(() => decrypt(blob, r));
});

test('legacy 1/256 collision: a scheme-0 blob whose IV begins 0x02 still decrypts (probe, fail-closed)', () => {
  let blob: Buffer;
  do { blob = encrypt('collision_secret', OLD); } while (blob[0] !== 0x02);
  // ...via the id-less key
  assert.equal(decrypt(blob, loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD), VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)}` })), 'collision_secret');
  // ...and via a listed key only
  assert.equal(decrypt(blob, loadKeyring({ VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)},k2019:${b64(OLD)}` })), 'collision_secret');
});

test('legacy collision probe does not mask a REAL unknown-id failure', () => {
  // A genuine keyed row whose id is missing from the ring: the legacy probe (which fails, the
  // blob is not scheme-0) must not swallow the actionable unknown-id error.
  const blob = encrypt('tok', ring({ id: 'gone', key: NEW }));
  const reader = ring({ id: 'k2025', key: randomBytes(32) }, [], OLD);
  assert.throws(() => decrypt(blob, reader), /gone/);
});

test('corrupt keyed header (idLen past the blob / invalid charset) fails closed without echoing bytes', () => {
  // Not decryptable as scheme-0 either → must throw, and the message must not embed raw header bytes.
  const junk = Buffer.concat([Buffer.from([0x02, 200]), randomBytes(40)]);
  assert.throws(
    () => decrypt(junk, ring({ id: 'k2025', key: NEW }, [], OLD)),
    (e: Error) => {
      assert.ok(!e.message.includes(junk.subarray(2, 10).toString('latin1')), 'no raw bytes in error');
      return true;
    },
  );
});

// ---------------------------------------------------------------------------------------------
// seal()/open(): the async storage entry points must dispatch identically, with or without an
// envelope provider in play.
// ---------------------------------------------------------------------------------------------

const KEK = randomBytes(32);
function aesWrap(dek: Buffer): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', KEK, iv);
  const ct = Buffer.concat([c.update(dek), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}
const envelope: EnvelopeProvider = {
  async wrapDataKey(dek) { return aesWrap(dek); },
  async unwrapDataKey(w) {
    const d = createDecipheriv('aes-256-gcm', KEK, w.subarray(0, 12));
    d.setAuthTag(w.subarray(12, 28));
    return Buffer.concat([d.update(w.subarray(28)), d.final()]);
  },
};

test('seal with a keyed primary writes scheme-2; open reads it back (no envelope)', async () => {
  const r = ring({ id: 'k2025', key: NEW }, [{ id: 'k2019', key: OLD }]);
  const blob = await seal('tok', r);
  assert.equal(blob[0], 0x02);
  assert.equal(await open(blob, r), 'tok');
});

test('seal with an id-less keyring stays byte-layout legacy (no scheme byte)', async () => {
  const r = loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD) });
  const blob = await seal('tok', r);
  assert.equal(blob.length, 12 + 16 + 3);
  assert.equal(decrypt(blob, OLD), 'tok'); // an OLD binary reads bytes written by the new one
});

test('envelope rows stay 0x01 and round-trip when a keyring (not a bare Buffer) is passed', async () => {
  const r = ring({ id: 'k2025', key: NEW }, [], OLD);
  const blob = await seal('tok_env', r, envelope);
  assert.equal(blob[0], 0x01);
  assert.equal(await open(blob, r, envelope), 'tok_env');
});

test('open routes scheme-2 rows to the keyed path even when an envelope provider is configured', async () => {
  // direct→KMS migration: old keyed rows must keep reading after envelope mode is enabled.
  const r = ring({ id: 'k2025', key: NEW });
  const blob = await seal('tok', r); // keyed direct row
  assert.equal(await open(blob, r, envelope), 'tok');
});

test('open still recovers a legacy 0x01-IV collision row under a keyring with an envelope set', async () => {
  let blob: Buffer;
  do { blob = encrypt('collision_secret', OLD); } while (blob[0] !== 0x01);
  const r = ring({ id: 'k2025', key: NEW }, [{ id: 'k2019', key: OLD }]);
  assert.equal(await open(blob, r, envelope), 'collision_secret');
});

// ---------------------------------------------------------------------------------------------
// tryDecryptDirect: the introspection used by `vouchr rekey` to attribute blobs to keys/schemes.
// ---------------------------------------------------------------------------------------------

test('tryDecryptDirect attributes each blob to the scheme + key that decrypted it', async () => {
  const r = loadKeyring({ VOUCHR_MASTER_KEY: b64(OLD), VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)},k2019:${b64(OLD)}` });

  const s0 = tryDecryptDirect(encrypt('a', OLD), r);
  assert.deepEqual(s0, { ok: true, plaintext: 'a', scheme: 0, keyId: null });

  const s2 = tryDecryptDirect(encrypt('b', r), r);
  assert.deepEqual(s2, { ok: true, plaintext: 'b', scheme: 2, keyId: 'k2025' });

  // scheme-0 attributed to a LISTED key when no id-less key matches
  const listedOnly = loadKeyring({ VOUCHR_MASTER_KEYS: `k2025:${b64(NEW)},k2019:${b64(OLD)}` });
  const s0listed = tryDecryptDirect(encrypt('c', OLD), listedOnly);
  assert.deepEqual(s0listed, { ok: true, plaintext: 'c', scheme: 0, keyId: 'k2019' });

  // unknown key id → reported as such, with the (charset-validated) id
  const unk = tryDecryptDirect(encrypt('d', ring({ id: 'gone', key: NEW })), listedOnly);
  assert.equal(unk.ok, false);
  assert.deepEqual(unk, { ok: false, reason: 'unknown-key-id', keyId: 'gone' });

  // an envelope row is not directly decryptable → maybe-envelope (rekey skips it)
  const env = await seal('e', OLD, envelope);
  assert.deepEqual(tryDecryptDirect(env, r), { ok: false, reason: 'maybe-envelope' });

  // garbage under no configured key
  const und = tryDecryptDirect(encrypt('f', randomBytes(32)), r);
  assert.deepEqual(und, { ok: false, reason: 'undecryptable' });
});

test('toKeyring: a bare Buffer normalizes to a single id-less keyring', () => {
  const r = toKeyring(OLD);
  assert.equal(r.primary.id, null);
  assert.equal(r.legacy.length, 1);
  assert.equal(r.byId.size, 0);
  const same = toKeyring(r);
  assert.equal(same, r, 'an existing keyring passes through');
});
