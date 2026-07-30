/**
 * Reference Express server.
 *
 * Run with:  npx tsx examples/server.ts
 *
 * Endpoints:
 *   POST /enroll        { clientId, publicKeyPem }         -> register device key
 *   POST /v1/order      (integrity headers required)       -> protected route
 *
 * In production: back the stores with Redis/DB, keep NATIVE_SECRET out of the
 * repo, and verify a Play Integrity / App Attest token on /enroll.
 */
import express from 'express';
import {
  integrityMiddleware,
  enrollmentHandler,
  rawBodySaver,
  InMemoryClientStore,
  InMemoryNonceStore,
} from '../src/index.js';

const app = express();
app.use(express.json({ verify: rawBodySaver }));

const clientStore = new InMemoryClientStore();
const nonceStore = new InMemoryNonceStore();

const NATIVE_SECRET = process.env.NATIVE_SECRET ?? 'CHANGE_ME_build_secret';
// The app-binding strings you accept (from AppIntegrity.bindingString()).
const ALLOWED_BINDINGS = (process.env.ALLOWED_BINDINGS ?? '').split(',').filter(Boolean);

// Enrollment is unprotected here for brevity — gate it with attestation!
app.post('/enroll', enrollmentHandler(clientStore));

// Everything below requires a valid signed request.
app.use(
  integrityMiddleware({
    clientStore,
    nonceStore,
    nativeSecret: NATIVE_SECRET,
    allowedBindings: ALLOWED_BINDINGS,
  }),
);

app.post('/v1/order', (req, res) => {
  res.json({ ok: true, client: req.integrity?.clientId, received: req.body });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`app-integrity example server on :${port}`));
