# App Integrity Protocol v1

Single source of truth shared by the client (`flutter_app_integrity`) and the
server verifier (`app-integrity-node`). Both sides MUST build the canonical
string **byte-for-byte identically**.

## Canonical request string

```
timestamp=<unixMillis>\n
<METHOD> <path>\n
<sha256hex(body)>\n
<clientId>\n
<nonce>
```

- Lines are joined with a single `\n` (LF, 0x0A). No trailing newline.
- `<unixMillis>` — client clock in milliseconds, decimal string.
- `<METHOD>` — HTTP method, **upper-case** (`POST`, `GET`, …).
- `<path>` — request path only (no scheme/host/query unless you decide query is
  part of the signature; if so, define it here and keep both sides in sync).
- `sha256hex(body)` — lower-case hex SHA-256 of the exact request body bytes
  (empty body ⇒ hash of zero bytes).
- `<clientId>` — opaque per-device id assigned at enrollment.
- `<nonce>` — 128-bit random, base64url **without** padding.

## Headers

| Header | Meaning |
|---|---|
| `timestamp` | same `<unixMillis>` as in the canonical string |
| `x-client-id` | `<clientId>` |
| `x-nonce` | `<nonce>` |
| `x-sig1` | base64(DER ECDSA P-256, SHA-256) over the canonical string |
| `x-sig2` | base64(HMAC-SHA256) over `canonical || 0x1f || binding` |
| `x-att` | (optional) platform attestation token bound to `<nonce>` |

`binding` = provider-specific app identity string:
- Android: `packageName|signingCertSha256Hex|flags`
- iOS: `bundleId||flags`

## Server verification order (fail fast)

1. **Timestamp window:** `abs(now - timestamp) <= 300_000 ms`, else reject.
2. **Nonce replay:** reject if `x-nonce` already seen; else store with TTL = window.
3. **Rebuild canonical** from `method`, `path`, `sha256hex(rawBody)`, `x-client-id`,
   `x-nonce`, `timestamp` — byte-exact.
4. **sig1:** ECDSA-verify against the client's enrolled public key. Reject on fail.
5. **sig2:** recompute HMAC with the per-build secret + expected `binding`.
   Constant-time compare. (May be a soft signal instead of hard reject.)
6. **att** (if present/due): verify Play Integrity / App Attest token against
   Google/Apple, bind verdict to `x-nonce` / `x-client-id`.

## Enrollment

On first launch the client generates its hardware key and sends the **public key
PEM** (+ ideally a fresh attestation token) to the server, which stores
`clientId -> publicKey`. Rotate with a `keyId` if needed.

## Versioning

Bump this document's version and add a `x-proto: 1` header if you evolve the
canonical layout, so old clients can be handled explicitly.
