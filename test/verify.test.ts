import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign, createHmac } from 'node:crypto';
import { buildCanonical, IntegrityHeaders } from '../src/canonical.js';
import { verifyRequest } from '../src/verify.js';
import { InMemoryClientStore, InMemoryNonceStore } from '../src/stores.js';

const CLIENT_ID = 'test-client';
const BINDING = 'com.example.app|abc123certsha256|release';
const SECRET = 'unit-test-secret';
const NOW = 1_730_000_000_000;

/** Simulate exactly what the Flutter client does. */
function signAsClient(privateKeyPem: string, opts: {
  method: string;
  path: string;
  body: Buffer;
  nonce: string;
  timestamp: string;
}) {
  const canonical = buildCanonical({
    method: opts.method,
    path: opts.path,
    body: opts.body,
    clientId: CLIENT_ID,
    timestamp: opts.timestamp,
    nonce: opts.nonce,
  });
  const bytes = Buffer.from(canonical, 'utf8');
  const sig1 = cryptoSign('sha256', bytes, { key: privateKeyPem, dsaEncoding: 'der' }).toString('base64');
  const sig2 = createHmac('sha256', SECRET)
    .update(bytes)
    .update(Buffer.from([0x1f]))
    .update(Buffer.from(BINDING, 'utf8'))
    .digest('base64');
  return {
    [IntegrityHeaders.timestamp]: opts.timestamp,
    [IntegrityHeaders.clientId]: CLIENT_ID,
    [IntegrityHeaders.nonce]: opts.nonce,
    [IntegrityHeaders.sig1]: sig1,
    [IntegrityHeaders.sig2]: sig2,
  } as Record<string, string>;
}

function newKeys() {
  return generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

async function setup() {
  const { publicKey, privateKey } = newKeys();
  const clientStore = new InMemoryClientStore();
  await clientStore.setPublicKey(CLIENT_ID, publicKey);
  const nonceStore = new InMemoryNonceStore();
  const opts = {
    clientStore,
    nonceStore,
    nativeSecret: SECRET,
    allowedBindings: [BINDING],
    now: () => NOW,
  };
  return { privateKey, opts };
}

test('valid signed request passes', async () => {
  const { privateKey, opts } = await setup();
  const body = Buffer.from('{"amount":42}', 'utf8');
  const headers = signAsClient(privateKey, {
    method: 'POST', path: '/v1/order', body, nonce: 'n1', timestamp: String(NOW),
  });
  const r = await verifyRequest({ method: 'POST', path: '/v1/order', body, headers }, opts);
  assert.equal(r.ok, true);
  assert.equal(r.clientId, CLIENT_ID);
});

test('tampered body fails sig1', async () => {
  const { privateKey, opts } = await setup();
  const body = Buffer.from('{"amount":42}', 'utf8');
  const headers = signAsClient(privateKey, {
    method: 'POST', path: '/v1/order', body, nonce: 'n2', timestamp: String(NOW),
  });
  const tampered = Buffer.from('{"amount":999}', 'utf8');
  const r = await verifyRequest({ method: 'POST', path: '/v1/order', body: tampered, headers }, opts);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-sig1');
});

test('replayed nonce fails', async () => {
  const { privateKey, opts } = await setup();
  const body = Buffer.from('{}', 'utf8');
  const headers = signAsClient(privateKey, {
    method: 'POST', path: '/v1/x', body, nonce: 'dup', timestamp: String(NOW),
  });
  const first = await verifyRequest({ method: 'POST', path: '/v1/x', body, headers }, opts);
  assert.equal(first.ok, true);
  const second = await verifyRequest({ method: 'POST', path: '/v1/x', body, headers }, opts);
  assert.equal(second.ok, false);
  assert.equal(second.reason, 'replay');
});

test('stale timestamp fails', async () => {
  const { privateKey, opts } = await setup();
  const body = Buffer.from('{}', 'utf8');
  const oldTs = String(NOW - 10 * 60_000);
  const headers = signAsClient(privateKey, {
    method: 'POST', path: '/v1/x', body, nonce: 'old', timestamp: oldTs,
  });
  const r = await verifyRequest({ method: 'POST', path: '/v1/x', body, headers }, opts);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'timestamp-out-of-window');
});

test('unknown client fails', async () => {
  const { privateKey, opts } = await setup();
  const body = Buffer.from('{}', 'utf8');
  const headers = signAsClient(privateKey, {
    method: 'POST', path: '/v1/x', body, nonce: 'u1', timestamp: String(NOW),
  });
  headers[IntegrityHeaders.clientId] = 'someone-else';
  const r = await verifyRequest({ method: 'POST', path: '/v1/x', body, headers }, opts);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unknown-client');
});

test('wrong sig2 binding fails', async () => {
  const { privateKey, opts } = await setup();
  const body = Buffer.from('{}', 'utf8');
  const headers = signAsClient(privateKey, {
    method: 'POST', path: '/v1/x', body, nonce: 'b1', timestamp: String(NOW),
  });
  // server expects a different binding
  const badOpts = { ...opts, allowedBindings: ['other|cert|release'] };
  const r = await verifyRequest({ method: 'POST', path: '/v1/x', body, headers }, badOpts);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-sig2');
});
