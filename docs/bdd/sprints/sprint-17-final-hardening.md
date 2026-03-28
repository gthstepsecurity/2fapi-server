# Sprint 17 — Final Production Hardening

> **Goal**: Fix ALL findings from the 7th Red Team audit (post-stub-elimination). Zero open findings.
> **Bounded Context**: Cross-cutting (infrastructure adapters)
> **Scenarios**: 7 findings (1 CRITICAL, 1 HIGH, 3 MEDIUM, 2 LOW)
> **Prerequisites**: Sprint 8B (real infrastructure), fix/production-no-stubs (26 stubs eliminated)
> **Key deliverables**: Real Ristretto255 generators, Redis Lua fix, constant-time rotation, secure IDs

---

## Red Team Audit Summary (7th pass — post-stub-elimination)

### Tests Performed

- **4 teams**: Crypto, Logic, Infrastructure, Advanced
- **Focus**: 15 new adapter files created to replace 26 stubs
- **Method**: Code review of every new adapter line-by-line
- **Scope**: production-services.ts, all bridge adapters, all NAPI wrappers, bootstrap, environment config

### Confirmed Secure (no findings)

| Area | Evidence |
|------|----------|
| SQL Injection | All PG adapters use parameterized queries ($1, $2) — verified in 6 files |
| Redis Injection | All keys built from constant prefixes + validated identifiers |
| Zero stubs in production | 0 Stub* imports in production-services.ts |
| Domain separation tags | Distinct tags per operation: PoP, Rotation-Current, Rotation-New, Reactivation |
| Fail-closed pattern | All PG bridges return false/null on error (except lockout — finding #5) |
| Environment switch | Only exact string "production" triggers production mode |
| BIP-39 wordlist integrity | SHA-256 verified at module load |
| Audit logger resilience | Catches all errors, falls back to console |
| Connection pool | Single shared pg.Pool, no leaks |

---

## Finding 1 (CRITICAL): Placeholder Generators G/H

```gherkin
Feature: Real Ristretto255 Generators in Production
  As the authentication server
  I want to use the real Ristretto255 generators G and H
  So that the ZKP protocol is mathematically sound

  Scenario: Production factory uses generators derived from Rust crypto core
    Given the production service factory is initialized
    When the generators G and H are loaded
    Then G is the Ristretto255 basepoint from curve25519-dalek
    And H is derived via hash-to-point with domain separator "2FApi-Pedersen-GeneratorH-v1"
    And both are valid 32-byte compressed Ristretto255 points
    And neither is the identity element

  Scenario: Placeholder generators are rejected in production
    Given generators filled with 0x01 or 0x02 repeating bytes
    When they are validated as Ristretto255 points
    Then validation fails because they are not valid compressed Ristretto255 encodings
```

**File**: `src/config/production-services.ts:228-229`
**Bug**: `generatorG = new Uint8Array(32).fill(0x01)` — not a valid Ristretto255 point
**Fix**: Load real generators from the NAPI Rust module via `nativeModule.getGeneratorG()` and `nativeModule.getGeneratorH()`

---

## Finding 2 (HIGH): Redis Lua Script Client Index Key Bug

```gherkin
Feature: Atomic Challenge Consumption Cleans Up Client Index
  As the verification engine
  I want challenge consumption to atomically remove the client index entry
  So that no orphan index entries remain in Redis

  Scenario: Consuming a challenge removes the challenge AND its client index entry
    Given Alice has a pending challenge "ch-001" in Redis
    And the client index "challenge:client:alice" points to "ch-001"
    When the challenge is consumed atomically
    Then the challenge key "challenge:ch-001" is deleted
    And the client index key "challenge:client:alice" is deleted

  Scenario: No orphan client index entries after consumption
    Given 100 challenges have been consumed
    When Redis is scanned for client index keys
    Then zero orphan index entries exist
```

**File**: `src/zk-verification/infrastructure/adapter/outgoing/redis-atomic-challenge-store.ts:64,80`
**Bug**: Lua KEYS[2] receives `CLIENT_INDEX_PREFIX + challengeId` instead of `CLIENT_INDEX_PREFIX + clientIdentifier`
**Fix**: Pass `CLIENT_INDEX_PREFIX + clientIdentifier` as KEYS[2] to the Lua script

---

## Finding 3 (MEDIUM): Rotation Proof Short-Circuit Timing Leak

```gherkin
Feature: Constant-Time Rotation Proof Verification
  As the client registration service
  I want rotation proof verification to be constant-time
  So that an attacker cannot determine which proof failed

  Scenario: Both proofs are verified regardless of first result
    Given Alice submits a rotation request with an invalid current proof and a valid new proof
    When the server verifies both proofs
    Then both verifications are executed (not short-circuited)
    And the response time is indistinguishable from a request where only the new proof is invalid
```

**File**: `src/client-registration/infrastructure/adapter/outgoing/napi-rotation-proof-verifier.ts:115`
**Bug**: `return currentValid && newValid` — JavaScript `&&` short-circuits, skipping second verify if first fails
**Fix**: Execute both verifications, then combine: `const result = currentValid & newValid; return result === 1;`

---

## Finding 4 (MEDIUM): Math.random() for Token/Monitoring IDs

```gherkin
Feature: Cryptographically Secure ID Generation
  As the system
  I want all generated IDs to use a cryptographic random source
  So that IDs are unpredictable and non-enumerable

  Scenario: Token IDs are generated with crypto.randomUUID
    When a new token ID is generated
    Then it uses Node.js crypto.randomUUID()
    And it is not based on Math.random()

  Scenario: Monitoring IDs are generated with crypto.randomUUID
    When a new monitoring event ID is generated
    Then it uses Node.js crypto.randomUUID()
```

**File**: `src/config/production-services.ts:339,353`
**Bug**: `Math.random().toString(36).slice(2)` — not cryptographically secure
**Fix**: Replace with `crypto.randomUUID()`

---

## Finding 5 (MEDIUM): Lockout Check Fail-Open on DB Error

```gherkin
Feature: Lockout Check Fails Closed
  As the authentication system
  I want lockout checks to fail closed on database errors
  So that an attacker cannot bypass lockout by overloading the database

  Scenario: Database error during lockout check blocks authentication
    Given the PostgreSQL connection pool is exhausted
    When Alice requests a challenge and the lockout check fails
    Then the challenge request is refused
    And the refusal is indistinguishable from a locked-out client
```

**File**: `src/authentication-challenge/infrastructure/adapter/outgoing/pg-client-status-bridge.ts:58-60`
**Bug**: Returns `{ isLockedOut: false }` on DB error — fail-open
**Fix**: Return `{ isLockedOut: true }` on error — fail-closed (block auth when DB is down)

---

## Finding 6 (LOW): ConfigAuthorizationChecker Open by Default

```gherkin
Feature: Authorization Checker Requires Explicit Configuration
  As an operator
  I want the authorization checker to require explicit audience configuration
  So that no deployment accidentally allows unrestricted access

  Scenario: Authorization checker without configuration rejects all requests
    Given the authorization checker is created without an audience allowlist
    When a token issuance is requested for audience "payment-api"
    Then the request is refused because no audiences are configured
```

**File**: `src/config/production-services.ts:248`, `src/api-access-control/infrastructure/adapter/outgoing/config-authorization-checker.ts:35`
**Bug**: `allowedAudiences = null` means "allow all"
**Fix**: `allowedAudiences = null` should mean "deny all" (fail-closed)

---

## Finding 7 (LOW): Non-Exhaustive Status Cast in PG Bridges

```gherkin
Feature: Exhaustive Status Handling in Database Bridges
  As the system
  I want database bridges to handle all possible status values
  So that unexpected values don't silently pass through

  Scenario: Unknown status value from database is treated as "unknown"
    Given the clients table contains a row with status "pending_activation"
    When the commitment lookup queries this client
    Then the client status is returned as "unknown"
    And no runtime error occurs
```

**File**: `src/zk-verification/infrastructure/adapter/outgoing/pg-commitment-lookup.ts:39`
**Bug**: Cast trusts DB value without validation
**Fix**: Map known values explicitly, default to "unknown" for anything else

---

## TDD Implementation Order

1. **RED**: Real generators loaded from NAPI Rust module
2. **RED**: Redis Lua script uses correct client index key
3. **RED**: Rotation proof executes both verifications (no short-circuit)
4. **RED**: Token/monitoring IDs use crypto.randomUUID()
5. **RED**: Lockout check returns locked on DB error (fail-closed)
6. **RED**: Authorization checker denies all when no config (fail-closed)
7. **RED**: Status cast maps unknown values to "unknown"
