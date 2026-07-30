import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCanonical, sha256Hex } from '../src/canonical.js';

test('canonical string matches the documented layout (cross-checks the Dart client)', () => {
  const body = Buffer.from('{"amount":42}', 'utf8');
  const canonical = buildCanonical({
    method: 'post', // lower-case in -> upper-case out
    path: '/v1/order',
    body,
    clientId: 'client-abc',
    timestamp: '1730000000000',
    nonce: 'fixed-nonce',
  });
  const hash = sha256Hex(body);
  assert.equal(
    canonical,
    `timestamp=1730000000000\nPOST /v1/order\n${hash}\nclient-abc\nfixed-nonce`,
  );
  assert.match(hash, /^[0-9a-f]{64}$/);
});
