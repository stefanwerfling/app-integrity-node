import { createHash } from 'node:crypto';

/** Standard header names (must match the client / PROTOCOL.md). */
export const IntegrityHeaders = {
  timestamp: 'timestamp',
  clientId: 'x-client-id',
  nonce: 'x-nonce',
  sig1: 'x-sig1',
  sig2: 'x-sig2',
  attestation: 'x-att',
} as const;

export function sha256Hex(body: Buffer | Uint8Array): string {
  return createHash('sha256').update(body).digest('hex');
}

/**
 * Build the canonical request string. MUST be byte-identical to the client.
 *
 * ```
 * timestamp=<ms>\n<METHOD> <path>\n<sha256hex(body)>\n<clientId>\n<nonce>
 * ```
 */
export function buildCanonical(params: {
  method: string;
  path: string;
  body: Buffer | Uint8Array;
  clientId: string;
  timestamp: string;
  nonce: string;
}): string {
  const { method, path, body, clientId, timestamp, nonce } = params;
  return (
    `timestamp=${timestamp}\n` +
    `${method.toUpperCase()} ${path}\n` +
    `${sha256Hex(body)}\n` +
    `${clientId}\n` +
    `${nonce}`
  );
}
