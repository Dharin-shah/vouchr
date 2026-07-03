import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  connectedBlocks,
  consentDeniedBlocks,
  statusBlocks,
  disconnectConfirmBlocks,
  homeView,
  DISCONNECT_ACTION,
} from '../src/adapters/blocks';

// Block Kit is untyped here (unknown[]); cast to any for structural probing.
const j = (b: unknown) => JSON.stringify(b);

test('connectedBlocks: interpolates provider + channel and shows how to disconnect', () => {
  const b = connectedBlocks('github', { channel: 'C123', scope: 'repo' }) as any[];
  assert.ok(Array.isArray(b));
  assert.equal(b[0].type, 'section');
  assert.match(b[0].text.text, /github connected/i);
  assert.match(j(b), /<#C123>/); // channel mention
  assert.match(j(b), /repo/); // scope
  assert.match(j(b), /\/vouchr disconnect github/);
});

test('connectedBlocks: null channel renders a DM scope', () => {
  const b = connectedBlocks('github', { channel: null }) as any[];
  assert.match(j(b), /your DMs/);
});

test('consentDeniedBlocks: states provider, default reason, and next step', () => {
  const b = consentDeniedBlocks('stripe') as any[];
  assert.equal(b[0].type, 'section');
  assert.match(b[0].text.text, /stripe not authorized/i);
  assert.match(j(b), /nothing was sent/i);
  assert.match(j(b), /\/vouchr connect stripe/);
});

test('consentDeniedBlocks: uses a supplied reason', () => {
  const b = consentDeniedBlocks('stripe', 'You clicked deny.') as any[];
  assert.match(j(b), /You clicked deny\./);
});

test('statusBlocks: empty state prompts to connect', () => {
  const b = statusBlocks([]) as any[];
  assert.equal(b.length, 1);
  assert.match(b[0].text.text, /no connections/i);
});

test('statusBlocks: lists each connection with channel + mode', () => {
  const b = statusBlocks([
    { provider: 'github', channel: 'C1', mode: 'shared' },
    { provider: 'stripe', channel: null, mode: 'per-user' },
  ]) as any[];
  assert.equal(b[0].type, 'header');
  const list = b[1].text.text as string;
  assert.match(list, /github/);
  assert.match(list, /<#C1>/);
  assert.match(list, /shared/);
  assert.match(list, /your DMs/);
  assert.match(list, /per-user/);
});

test('disconnectConfirmBlocks: destructive button carries provider in value', () => {
  const b = disconnectConfirmBlocks('github') as any[];
  const actions = b.find((x) => x.type === 'actions');
  assert.ok(actions);
  const btn = actions.elements[0];
  assert.equal(btn.type, 'button');
  assert.equal(btn.action_id, DISCONNECT_ACTION);
  assert.equal(btn.value, 'github');
  assert.equal(btn.style, 'danger');
});

test('homeView: returns a home view listing connections and available providers', () => {
  const v = homeView({
    connections: [{ provider: 'github', channel: 'C1', mode: 'shared' }],
    providers: ['github', 'stripe'],
  }) as any;
  assert.equal(v.type, 'home');
  assert.ok(Array.isArray(v.blocks));
  const s = j(v.blocks);
  assert.match(s, /github/); // connected
  assert.match(s, /stripe/); // available (not connected)
  // github is already connected, so it should not appear under "Available providers"
  const avail = v.blocks.find((x: any) => x.type === 'section' && /Available providers/.test(x.text?.text ?? ''));
  assert.ok(avail);
  assert.doesNotMatch(avail.text.text, /github/);
});

test('homeView: empty connections still renders a valid home view', () => {
  const v = homeView({ connections: [], providers: ['github'] }) as any;
  assert.equal(v.type, 'home');
  assert.match(j(v.blocks), /None yet/i);
});
