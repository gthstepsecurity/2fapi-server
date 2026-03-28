# @2fapi/server

> 2FApi Verification Engine — Zero-Knowledge Proof authentication server.

## License

This package is licensed under the [Business Source License 1.1](./LICENSE).

**Permitted use**: Authenticating your own APIs and your own customers' API calls.

**Not permitted**: Offering ZK-proof API authentication verification as a commercial service to third parties.

The license converts to Apache 2.0 on 2030-03-22.

For managed hosting without self-hosting, see [2FApi Cloud](https://2fapi.continuum-identity.com).

For alternative licensing, contact licensing@continuum-identity.com.

## Quick Start

```typescript
import { createServer } from "@2fapi/server";

const app = createServer({
  enrollClient: enrollmentService,
  requestChallenge: challengeService.requestChallenge,
  verifyProof: verificationService,
  issueToken: accessControlService.issueToken,
  validateToken: accessControlService.validateToken,
  revokeClient: lifecycleService.revokeClient,
  rotateCommitment: lifecycleService.rotateCommitment,
  rateLimiting: {
    global: { maxRequests: 10000, windowMs: 1000 },
    perIp: { maxRequests: 100, windowMs: 1000 },
  },
});

await app.listen({ port: 3000 });
```

## Architecture

5 bounded contexts, hexagonal architecture, strict TDD:

- **Client Registration** — Enrollment, commitment storage, rotation, revocation
- **Authentication Challenge** — Nonce generation, session management
- **Zero-Knowledge Verification** — Sigma proof verification, Fiat-Shamir
- **API Access Control** — Token issuance, audience restriction, validation
- **Security Monitoring** — Lockout, audit trail, anomaly detection

## Security

- 1073 automated tests including 70 red team exploit attempts
- 4 internal security audit passes, 79 findings resolved
- 92.96% mutation testing kill rate
- Constant-time verification, timing-safe error responses
- Provably secure under DLOG assumption on Ristretto255
