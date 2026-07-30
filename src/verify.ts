import { createHmac, timingSafeEqual, verify as cryptoVerify } from 'node:crypto';
import { buildCanonical, IntegrityHeaders } from './canonical.js';
import type { ClientStore, NonceStore } from './stores.js';

export type HeaderMap = Record<string, string | string[] | undefined>;

export interface VerifyInput {
  method: string;
  path: string;
  /** The exact raw request-body bytes. */
  body: Buffer;
  headers: HeaderMap;
}

export interface VerifyOptions {
  clientStore: ClientStore;
  nonceStore: NonceStore;
  /** Shared per-build secret for sig2. Omit to skip sig2 verification. */
  nativeSecret?: Buffer | string;
  /**
   * Allowed app-binding strings for sig2 (e.g. `pkg|certSha256|release`).
   * At least one must match. Ignored if `nativeSecret` is not set.
   */
  allowedBindings?: string[];
  /** Accepted clock skew in ms (default 300_000 = 5 min). */
  windowMs?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

export type VerifyReason =
  | 'missing-headers'
  | 'timestamp-out-of-window'
  | 'replay'
  | 'unknown-client'
  | 'bad-sig1'
  | 'bad-sig2';

export interface VerifyResult {
  ok: boolean;
  clientId?: string;
  reason?: VerifyReason;
}

function header(h: HeaderMap, name: string): string | undefined {
  const v = h[name] ?? h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Verify a signed request per PROTOCOL.md. Order (fail fast):
 * timestamp window → nonce replay → sig1 (ECDSA) → sig2 (HMAC).
 * Attestation (`x-att`) is out of scope here — verify it separately against
 * Google/Apple and bind the verdict to the nonce/clientId.
 */
export async function verifyRequest(
  input: VerifyInput,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const windowMs = opts.windowMs ?? 300_000;
  const now = (opts.now ?? Date.now)();

  const timestamp = header(input.headers, IntegrityHeaders.timestamp);
  const clientId = header(input.headers, IntegrityHeaders.clientId);
  const nonce = header(input.headers, IntegrityHeaders.nonce);
  const sig1 = header(input.headers, IntegrityHeaders.sig1);
  const sig2 = header(input.headers, IntegrityHeaders.sig2);

  if (!timestamp || !clientId || !nonce || !sig1) {
    return { ok: false, reason: 'missing-headers' };
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > windowMs) {
    return { ok: false, reason: 'timestamp-out-of-window' };
  }

  const fresh = await opts.nonceStore.checkAndRemember(nonce, windowMs);
  if (!fresh) return { ok: false, reason: 'replay' };

  const publicKeyPem = await opts.clientStore.getPublicKey(clientId);
  if (!publicKeyPem) return { ok: false, reason: 'unknown-client' };

  const canonical = buildCanonical({
    method: input.method,
    path: input.path,
    body: input.body,
    clientId,
    timestamp,
    nonce,
  });
  const canonicalBytes = Buffer.from(canonical, 'utf8');

  // sig1: ECDSA P-256 / SHA-256, DER-encoded signature.
  let sig1Ok = false;
  try {
    sig1Ok = cryptoVerify(
      'sha256',
      canonicalBytes,
      { key: publicKeyPem, dsaEncoding: 'der' },
      Buffer.from(sig1, 'base64'),
    );
  } catch {
    sig1Ok = false;
  }
  if (!sig1Ok) return { ok: false, reason: 'bad-sig1' };

  // sig2: HMAC-SHA256 over canonical || 0x1f || binding.
  if (opts.nativeSecret) {
    if (!sig2) return { ok: false, reason: 'bad-sig2' };
    const provided = Buffer.from(sig2, 'base64');
    const bindings = opts.allowedBindings ?? [];
    const match = bindings.some((binding) => {
      const expected = createHmac('sha256', opts.nativeSecret!)
        .update(canonicalBytes)
        .update(Buffer.from([0x1f]))
        .update(Buffer.from(binding, 'utf8'))
        .digest();
      return provided.length === expected.length && timingSafeEqual(provided, expected);
    });
    if (!match) return { ok: false, reason: 'bad-sig2' };
  }

  return { ok: true, clientId };
}
