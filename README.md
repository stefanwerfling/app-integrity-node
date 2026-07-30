# app-integrity-node

Server-side verification for the **App Integrity** protocol — the backend
companion to the [`flutter_app_integrity`](../flutter_app_integrity) Flutter
plugin. Verifies that an API request came from a genuine, untampered instance of
**your** app and rejects tampering and replay.

Both sides implement the same [`PROTOCOL.md`](PROTOCOL.md) — keep them in sync.

## What it checks

For each request, in order (fail fast):

1. **Timestamp window** (default ±5 min)
2. **Nonce replay** (per-request nonce, TTL cache)
3. **sig1** — ECDSA P-256 / SHA-256 signature against the device's enrolled public key
4. **sig2** — HMAC second factor bound to the app signing certificate

Platform attestation (`x-att`, Play Integrity / App Attest) is verified
separately against Google/Apple — this library covers the signature + replay
layer and gives you a hook to add attestation.

Zero runtime dependencies (uses `node:crypto`); Express adapter is optional.

## Install

```bash
npm install app-integrity-node
# express is an optional peer dependency (only for the middleware)
```

## Usage (Express)

```ts
import express from 'express';
import {
  integrityMiddleware, enrollmentHandler, rawBodySaver,
  InMemoryClientStore, InMemoryNonceStore,
} from 'app-integrity-node';

const app = express();
app.use(express.json({ verify: rawBodySaver })); // capture raw bytes for hashing

const clientStore = new InMemoryClientStore(); // swap for Redis/DB in prod
const nonceStore = new InMemoryNonceStore();

app.post('/enroll', enrollmentHandler(clientStore)); // gate with attestation!

app.use(integrityMiddleware({
  clientStore,
  nonceStore,
  nativeSecret: process.env.NATIVE_SECRET!,   // same secret as the app build
  allowedBindings: [process.env.APP_BINDING!], // from AppIntegrity.bindingString()
}));

app.post('/v1/order', (req, res) => {
  res.json({ ok: true, client: req.integrity?.clientId });
});
```

Runnable reference: [`examples/server.ts`](examples/server.ts) (`npx tsx examples/server.ts`).

## Usage (framework-agnostic core)

```ts
import { verifyRequest } from 'app-integrity-node';

const result = await verifyRequest(
  { method, path, body /* Buffer */, headers },
  { clientStore, nonceStore, nativeSecret, allowedBindings },
);
if (!result.ok) reject(result.reason); // 'bad-sig1' | 'replay' | ...
```

## Production notes

- **Stores:** replace `InMemory*` with Redis/DB. The nonce cache TTL must cover
  the timestamp window; the client store maps `clientId -> publicKeyPem`.
- **Enrollment:** only accept a new device key together with a fresh, verified
  attestation token, so attackers can't register their own keys.
- **`nativeSecret` / `allowedBindings`:** must match the app build. Rotate with a
  `keyId` when you ship new secrets. You may treat `sig2` as a soft signal
  instead of a hard reject to avoid false positives.
- **Raw body:** hash the exact received bytes — use `rawBodySaver` (or your own
  raw-body capture). Any re-serialization will break the signature.

## API

- `verifyRequest(input, options) => Promise<VerifyResult>`
- `integrityMiddleware(options)` · `enrollmentHandler(store)` · `rawBodySaver`
- `buildCanonical`, `sha256Hex`, `IntegrityHeaders`
- `ClientStore`, `NonceStore`, `InMemoryClientStore`, `InMemoryNonceStore`

## Scripts

```bash
npm run build      # tsc -> dist/
npm test           # node --test (crypto round-trip + negatives)
npm run typecheck
```

## License

MIT © Stefan Werfling
