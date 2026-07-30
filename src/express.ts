import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { verifyRequest, type VerifyOptions, type VerifyResult } from './verify.js';
import type { ClientStore } from './stores.js';

// Augment Express Request with the fields we rely on / set.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      rawBody?: Buffer;
      integrity?: VerifyResult;
    }
  }
}

/**
 * Body parser that also stashes the raw bytes on `req.rawBody`, so the
 * integrity middleware can hash exactly what the client hashed.
 *
 * Usage: `app.use(express.json({ verify: rawBodySaver }))`
 */
export function rawBodySaver(req: Request, _res: Response, buf: Buffer): void {
  req.rawBody = Buffer.from(buf);
}

export interface IntegrityMiddlewareOptions extends VerifyOptions {
  /** Extract the raw body bytes (default: `req.rawBody`). */
  getRawBody?: (req: Request) => Buffer | undefined;
  /** Called on failure; default responds 401 JSON. */
  onFailure?: (req: Request, res: Response, result: VerifyResult) => void;
}

/** Express middleware that enforces request integrity. */
export function integrityMiddleware(opts: IntegrityMiddlewareOptions): RequestHandler {
  const getRawBody = opts.getRawBody ?? ((req: Request) => req.rawBody);
  const onFailure =
    opts.onFailure ??
    ((_req: Request, res: Response, result: VerifyResult) => {
      res.status(401).json({ error: 'integrity_check_failed', reason: result.reason });
    });

  return (req: Request, res: Response, next: NextFunction) => {
    const body = getRawBody(req) ?? Buffer.alloc(0);
    verifyRequest(
      { method: req.method, path: req.path, body, headers: req.headers },
      opts,
    )
      .then((result) => {
        req.integrity = result;
        if (result.ok) next();
        else onFailure(req, res, result);
      })
      .catch(next);
  };
}

/**
 * Minimal enrollment handler: stores `{ clientId, publicKeyPem }`.
 *
 * SECURE THIS: only accept an enrollment together with a fresh, verified
 * attestation token so that only genuine app instances can register a key.
 */
export function enrollmentHandler(clientStore: ClientStore): RequestHandler {
  return (req: Request, res: Response) => {
    const { clientId, publicKeyPem } = (req.body ?? {}) as {
      clientId?: string;
      publicKeyPem?: string;
    };
    if (!clientId || !publicKeyPem || !publicKeyPem.includes('BEGIN PUBLIC KEY')) {
      res.status(400).json({ error: 'clientId and publicKeyPem required' });
      return;
    }
    clientStore
      .setPublicKey(clientId, publicKeyPem)
      .then(() => res.json({ ok: true }))
      .catch(() => res.status(500).json({ error: 'store_failed' }));
  };
}
