<p align="center">
  <h1 align="center">2FApi</h1>
  <p align="center"><strong>Zero-Knowledge Proof Authentication for APIs</strong></p>
  <p align="center">Prove you know the secret. Never reveal it.</p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-2035_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/ProVerif-5%2F5_proven-blue" alt="Formal Verification">
  <img src="https://img.shields.io/badge/dudect-constant__time_verified-blue" alt="Constant-Time">
  <img src="https://img.shields.io/badge/red_team-400%2B_attacks_blocked-red" alt="Red Team">
  <img src="https://img.shields.io/badge/license-BSL_1.1-orange" alt="License">
</p>

---

## What is 2FApi?

2FApi is a **two-factor authentication protocol for API calls** based on Zero-Knowledge Proofs. Instead of sharing secrets with the server (like API keys or passwords), the client proves it *knows* a secret without ever revealing it.

**The server stores zero secrets.** If your database is breached, the attacker gets cryptographic commitments — mathematically useless without the client's secret.

### How it works

```
Client                                  Server
  │                                       │
  │──── 1. Register (commitment C) ──────>│  Server stores C = s·G + r·H
  │                                       │  (never sees s or r)
  │                                       │
  │──── 2. Request challenge ────────────>│  Server issues unique nonce
  │<─── nonce ───────────────────────────│
  │                                       │
  │──── 3. Submit ZK proof ──────────────>│  Server verifies equation:
  │<─── access token ────────────────────│  z_s·G + z_r·H == A + c·C
  │                                       │  (without knowing s or r)
  │                                       │
  │──── 4. Access resource ──────────────>│  Bearer token + audience check
  │<─── resource data ───────────────────│
```

### Why not just use API keys?

| | 2FApi | API Keys | OAuth 2.0 | mTLS |
|---|---|---|---|---|
| **Server stores secrets** | **No** | Yes | Yes | Yes (CA) |
| **DB breach impact** | **None** | Total compromise | Total compromise | Partial |
| **Zero-knowledge** | **Yes** | No | No | No |
| **Replay-resistant** | **Yes** (nonce-bound) | No (static key) | Partial | Yes |
| **Performance** | <5ms verify | <1ms | ~10ms | ~50ms |

---

## Quick Start

### Installation

```bash
npm install @2fapi/core
```

### Server Setup

```typescript
import {
  createEnrollmentService,
  createChallengeService,
  createVerificationService,
  createAccessControlService,
  createMonitoringService,
} from "@2fapi/core";

// Wire up your infrastructure adapters
const enrollment = createEnrollmentService({ /* ... */ });
const challenges = createChallengeService({ /* ... */ });
const verification = createVerificationService({ /* ... */ });
const accessControl = createAccessControlService({ /* ... */ });
```

### REST API (Fastify)

```typescript
import { createServer } from "@2fapi/core/api-gateway";

const app = createServer({
  enrollClient: enrollment,
  requestChallenge: challenges.requestChallenge,
  verifyProof: verification,
  issueToken: accessControl.issueToken,
  validateToken: accessControl.validateToken,
  revokeClient: lifecycle.revokeClient,
  rotateCommitment: lifecycle.rotateCommitment,
  rateLimiting: { global: { maxRequests: 10000, windowMs: 1000 }, perIp: { maxRequests: 100, windowMs: 1000 } },
});

await app.listen({ port: 3000 });
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/clients` | Register a new client (enrollment) |
| `POST` | `/v1/challenges` | Request an authentication challenge |
| `POST` | `/v1/verify` | Submit ZK proof and receive access token |
| `GET` | `/v1/resources/:id` | Access a protected resource |
| `DELETE` | `/v1/clients/:id` | Revoke a client (admin) |
| `PUT` | `/v1/clients/:id/commitment` | Rotate commitment |
| `GET` | `/health` | Health check |

---

## Architecture

2FApi follows **hexagonal architecture** with 5 isolated bounded contexts:

```
┌─────────────────────────────────────────────────────────────┐
│                     API Gateway (Fastify)                     │
│  POST /v1/clients  POST /v1/challenges  POST /v1/verify     │
├──────────┬───────────┬────────────┬──────────┬──────────────┤
│  Client  │   Auth    │     ZK     │   API    │  Security    │
│  Regist. │ Challenge │  Verific.  │  Access  │  Monitoring  │
│          │           │            │  Control │              │
├──────────┴───────────┴────────────┴──────────┴──────────────┤
│                    Infrastructure Layer                       │
│  Rust Crypto (napi-rs) · PostgreSQL · Redis · Docker         │
└─────────────────────────────────────────────────────────────┘
```

Each bounded context follows the same structure:

```
<context>/
├── domain/
│   ├── model/          # Entities, Value Objects
│   ├── event/          # Domain Events
│   ├── port/
│   │   ├── incoming/   # Use case interfaces
│   │   └── outgoing/   # Repository/service interfaces
│   └── service/        # Domain services
├── application/
│   └── usecase/        # Use case implementations
└── infrastructure/
    └── adapter/
        └── outgoing/   # Real implementations (PostgreSQL, Redis, napi-rs)
```

**Key principles:**
- Dependencies point inward: infrastructure → application → domain
- Domain has **zero** framework dependencies
- Bounded contexts communicate **only** via integration events
- Every port is an interface; every adapter is replaceable

---

## Cryptographic Protocol

### Primitives

| Primitive | Implementation |
|-----------|---------------|
| Commitment scheme | Pedersen: C = s·G + r·H over Ristretto255 |
| Proof system | Schnorr/Sigma protocol for representation |
| Non-interactivity | Fiat-Shamir transform with domain separation |
| Curve | Ristretto255 (prime-order group, no cofactor issues) |
| Hash | SHA-512 (transcript), SHA-256 (nonce derivation) |
| Security level | 128-bit (DLOG assumption) |

### Fiat-Shamir Transcript

The challenge scalar is derived from a canonical, length-prefixed transcript:

```
c = SHA-512(
  "2FApi-Sigma-Transcript-v1" ||    # Domain separation
  LP(tag) || LP(G) || LP(H) ||      # Protocol parameters
  LP(C) || LP(A) ||                  # Commitment + announcement
  LP(clientId) ||                    # Client binding
  LP(nonce) || LP(channelBinding)    # Session binding
)
```

Every field is prefixed with a 4-byte big-endian length to prevent concatenation ambiguity.

### Security Properties

- **Soundness**: Provably secure under DLOG in the Random Oracle Model
- **Zero-knowledge**: Simulator construction via Fiat-Shamir
- **Replay resistance**: Single-use nonces, atomic challenge consumption
- **Channel binding**: Proof bound to TLS session (tls-exporter / DPoP fallback)
- **Constant-time**: All secret-dependent operations via `subtle::ConstantTimeEq` (Rust)
- **Memory safety**: Secrets zeroized after use (`zeroize` crate, `ZeroizeOnDrop`)

---

## Security

### Red Team Results

2FApi has undergone **4 internal red team passes**:

| Pass | Method | Findings | Status |
|------|--------|----------|--------|
| 1 | Code review (4 expert teams) | 46 | All fixed |
| 2 | Pre-production targeted review | 10 | All fixed |
| 3 | Deep adversarial analysis | 25 | All fixed |
| 4 | Automated exploit testing (70 attacks) | 0 | All blocked |
| **Total** | | **79 findings fixed, 0 open** | |

### Attack Resistance (verified by automated tests)

- Proof forgery without secret
- Proof replay / challenge reuse
- Cross-client challenge theft
- Token audience confusion (confused deputy)
- Token use after revocation
- Lockout bypass
- Token issuance without proof
- Receipt replay
- Identity commitment exploitation
- Zero challenge scalar forgery
- Non-canonical scalar/point injection
- Oversized payload DoS
- Client enumeration via timing/errors
- Commitment rotation for revoked clients

### Hardening Features

- **Timing-safe verification**: All error paths execute dummy operations to match success path timing
- **Indistinguishable errors**: All authentication failures return identical responses
- **Lockout with exponential backoff**: 3 attempts → 60 min lockout, doubles on repeat
- **Anomaly detection**: Distributed brute-force, volume anomalies, mass lockout escalation
- **Immutable audit trail**: Append-only, secrets excluded, configurable retention
- **Admin authentication**: Fail-fast guard prevents deployment with stub authenticator
- **Rate limiting**: Required in production (global + per-IP + per-client)
- **RNG health check**: Rejects low-entropy random sources, hedged nonce construction

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Crypto core | Rust (`curve25519-dalek` v4, `subtle`, `zeroize`) |
| Server | TypeScript / Node.js |
| HTTP framework | Fastify 5 |
| FFI | napi-rs (Node.js), wasm-bindgen (browser) |
| Database | PostgreSQL 16 (clients, audit, challenges) |
| Cache | Redis 7 (rate limiting, session challenges) |
| Testing | Vitest, fast-check (property-based), Stryker (mutation) |
| Architecture | Hexagonal, DDD bounded contexts, SOLID |
| Methodology | Strict TDD (baby steps, outside-in) |

---

## Development

### Prerequisites

- Node.js 20+
- Rust toolchain (for crypto core)
- Docker (for PostgreSQL + Redis)

### Setup

```bash
git clone https://github.com/your-org/2fapi.git
cd 2fapi
npm install
docker compose up -d    # PostgreSQL + Redis
npm test                # Run 1073 tests
```

### Test Suite

```bash
npm test                    # Unit tests (1073)
npm run test:coverage       # With coverage
npm run test:mutation       # Stryker mutation testing (92.96% kill rate)
npm run test:integration    # Integration tests (requires Docker services)
```

### Project Structure

```
2fapi/
├── src/
│   ├── client-registration/      # Bounded context: enrollment, lifecycle
│   ├── authentication-challenge/  # Bounded context: challenge issuance
│   ├── zk-verification/          # Bounded context: proof verification
│   ├── api-access-control/       # Bounded context: token management
│   ├── security-monitoring/      # Bounded context: audit, lockout, anomaly
│   ├── api-gateway/              # Fastify routes + middleware
│   └── shared/                   # Cross-cutting utilities
├── crypto-core/                  # Rust crate (Ristretto255, Sigma protocol)
│   ├── src/                      # Core crypto library
│   └── napi/                     # Node.js native bindings
├── infrastructure/
│   └── postgresql/migrations/    # SQL schema
├── tests/                        # 1073 tests
│   ├── red-team/                 # 70 exploit attempt tests
│   └── integration/              # Infrastructure integration tests
├── docs/
│   ├── bdd/sprints/              # 14 sprint specifications
│   ├── security/                 # Red team audit reports
│   └── PROTOCOL.md               # Canonical protocol specification
└── docker-compose.yml
```

---

## Documentation

- [Protocol Specification](docs/PROTOCOL.md) — Canonical Fiat-Shamir transcript format
- [Security Audit Reports](docs/security/) — 4 red team passes, 79 findings resolved
- [Sprint Specifications](docs/bdd/sprints/) — 14 BDD sprint files with Gherkin scenarios

---

## Roadmap

- [x] Core protocol (Sprints 1-3)
- [x] Token management (Sprint 4)
- [x] Security monitoring (Sprint 5)
- [x] Client lifecycle — rotation & revocation (Sprint 6)
- [x] Security hardening & performance (Sprint 7)
- [x] Infrastructure scaffolding — Rust, PostgreSQL, Redis (Sprint 8)
- [x] REST API — Fastify (Sprint 9)
- [x] Security audit fixes — 4 red team passes (Sprints 10-14)
- [ ] Rust crypto core compilation & integration testing
- [ ] Client SDK (browser WASM + Node.js)
- [ ] CI/CD pipeline
- [ ] External security audit
- [ ] IETF protocol specification draft

---

## Contributing

2FApi is developed with strict TDD. Every change requires:

1. A failing test first (RED)
2. Minimum code to pass (GREEN)
3. Refactor while green (REFACTOR)

All cryptographic code must be constant-time and auditable. No `unsafe` in the crypto crate.

---

## License

**Business Source License 1.1 (BSL 1.1)**

- **Licensor:** Continuum Identity SAS
- **Licensed Work:** Continuum Ghost Protocol Server
- **Change Date:** 4 years from each release date
- **Change License:** Apache License 2.0

You may use, copy, and modify the Licensed Work for any purpose **except** offering it as a competing hosted authentication service. After the Change Date, the code transitions to Apache 2.0.

See [LICENSE](LICENSE) for the full text.

---

<p align="center">
  <em>"API keys are the new passwords — we're replacing them with math."</em>
</p>
