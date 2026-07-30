/**
 * Pluggable persistence. In production back these with Redis / your database;
 * the in-memory implementations are for development and tests only.
 */

/** Maps an enrolled clientId to its device public key (PEM, SPKI). */
export interface ClientStore {
  getPublicKey(clientId: string): Promise<string | undefined>;
  setPublicKey(clientId: string, publicKeyPem: string): Promise<void>;
}

/** Replay protection: returns true if the nonce is fresh (and records it). */
export interface NonceStore {
  /** True if `nonce` was not seen before (now remembered for `ttlMs`). */
  checkAndRemember(nonce: string, ttlMs: number): Promise<boolean>;
}

export class InMemoryClientStore implements ClientStore {
  private readonly keys = new Map<string, string>();
  async getPublicKey(clientId: string): Promise<string | undefined> {
    return this.keys.get(clientId);
  }
  async setPublicKey(clientId: string, publicKeyPem: string): Promise<void> {
    this.keys.set(clientId, publicKeyPem);
  }
}

export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();

  async checkAndRemember(nonce: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    this.sweep(now);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, now + ttlMs);
    return true;
  }

  private sweep(now: number): void {
    for (const [k, exp] of this.seen) {
      if (exp <= now) this.seen.delete(k);
    }
  }
}
