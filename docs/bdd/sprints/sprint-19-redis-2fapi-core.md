# Sprint 19 — redis-2fapi Core (Redis Module)

> **Goal**: Deliver the redis-2fapi Redis module providing ZKP authentication as custom Redis commands with key-level access control.
> **Bounded Context**: Cross-cutting (database-native authentication)
> **Scenarios**: 28 | Happy: 13 | Edge: 7 | Error: 8
> **Prerequisites**: Sprint 3 (verification core), Sprint 7 (hardening), crypto-core crate stable
> **Key deliverables**: redis-module-rs based module with ENROLL/CHALLENGE/VERIFY/STATUS/REVOKE commands, per-connection authentication, key-level ACL

---

## Feature 1: Module Loading (4 scenarios)

```gherkin
Feature: redis-2fapi Module Loading
  As a Redis administrator
  I want to load the redis-2fapi module into a running Redis server
  So that ZKP authentication commands become available

  Background:
    Given a Redis 7.0+ server is running
    And the redis_2fapi.so shared library has been compiled with redis-module-rs
    And the module registers under the name "2fapi"

  # --- Happy Path ---

  Scenario: MODULE LOAD registers all 2FAPI commands
    Given the module is not yet loaded
    When the administrator executes "MODULE LOAD /path/to/redis_2fapi.so"
    Then the module loads successfully
    And the following commands are registered:
      | Command           | Flags       |
      | 2FAPI.ENROLL      | write deny-oom |
      | 2FAPI.CHALLENGE   | write deny-oom |
      | 2FAPI.VERIFY      | write       |
      | 2FAPI.STATUS      | readonly    |
      | 2FAPI.REVOKE      | write       |
    And "MODULE LIST" includes a module named "2fapi" with version 1

  Scenario: Commands are registered with correct arity checks
    Given the 2fapi module is loaded
    When a client sends "2FAPI.ENROLL" with the wrong number of arguments
    Then Redis responds with a WrongArity error
    And the same arity enforcement applies to all 2FAPI commands

  Scenario: Module version is queryable
    Given the 2fapi module is loaded
    When the administrator executes "MODULE LIST"
    Then the entry for "2fapi" shows version 1
    And the module name matches the redis_module! declaration

  # --- Edge Case ---

  Scenario: MODULE UNLOAD removes all 2FAPI commands
    Given the 2fapi module is loaded
    And no 2FAPI keys exist in the database
    When the administrator executes "MODULE UNLOAD 2fapi"
    Then the module is unloaded successfully
    And "2FAPI.ENROLL" returns an unknown command error
    And "MODULE LIST" no longer includes "2fapi"
```

---

## Feature 2: Client Enrollment (6 scenarios)

```gherkin
Feature: Client Enrollment via redis-2fapi
  As an application developer
  I want to enroll clients with Pedersen commitments in Redis
  So that ZKP authentication is available for Redis-backed services

  Background:
    Given the 2fapi module is loaded in Redis
    And commitments are provided as hex-encoded 32-byte compressed Ristretto255 points
    And client data is stored as a Redis hash at key "2fapi:client:<client_id>"
    And the hash contains fields "commitment" (hex) and "status" (active|suspended|revoked)

  # --- Happy Path ---

  Scenario: ENROLL stores a valid commitment with active status
    Given Alice has computed a valid Pedersen commitment C_hex over Ristretto255
    When the application executes:
      """
      2FAPI.ENROLL alice-payments <C_hex>
      """
    Then Redis responds with "OK"
    And a hash key "2fapi:client:alice-payments" exists
    And HGET "2fapi:client:alice-payments" "commitment" returns C_hex
    And HGET "2fapi:client:alice-payments" "status" returns "active"

  Scenario: STATUS returns active for a newly enrolled client
    Given Alice has been enrolled via 2FAPI.ENROLL
    When the application executes "2FAPI.STATUS alice-payments"
    Then Redis responds with "active"

  # --- Error Path ---

  Scenario: ENROLL rejects invalid hex encoding
    When the application executes:
      """
      2FAPI.ENROLL mallory not-valid-hex-string
      """
    Then Redis responds with error "Invalid hex encoding for commitment"
    And no key "2fapi:client:mallory" is created

  Scenario: ENROLL rejects the identity element
    Given a hex-encoded commitment that decodes to the Ristretto255 identity element
    When the application executes "2FAPI.ENROLL mallory <identity_hex>"
    Then Redis responds with error "Commitment must not be the identity element"
    And no key "2fapi:client:mallory" is created

  Scenario: ENROLL rejects a non-canonical Ristretto255 encoding
    Given a 32-byte hex value that is not a valid compressed Ristretto255 point
    When the application executes "2FAPI.ENROLL mallory <non_canonical_hex>"
    Then Redis responds with error "Commitment is not a valid Ristretto255 point"
    And no key "2fapi:client:mallory" is created

  Scenario: ENROLL refuses duplicate enrollment for an existing client
    Given Alice is already enrolled with client_id = 'alice-payments'
    When the application executes "2FAPI.ENROLL alice-payments <different_commitment_hex>"
    Then Redis responds with error "Client already enrolled"
    And the existing commitment is not overwritten
```

---

## Feature 3: Challenge & Verification (8 scenarios)

```gherkin
Feature: Challenge Issuance and Proof Verification via redis-2fapi
  As the Redis authentication layer
  I want to issue challenges and verify ZK proofs
  So that clients can authenticate without revealing their secrets

  Background:
    Given the 2fapi module is loaded in Redis
    And Alice is enrolled with client_id = 'alice-payments', commitment C, and status = 'active'
    And challenges are stored as Redis hashes at "2fapi:challenge:<challenge_id>"
    And challenge hashes contain fields "client_id" and "nonce"
    And challenges have a Redis EXPIRE TTL of 120 seconds (2 minutes)
    And nonces are generated from 24 bytes of OS randomness (OsRng)
    And proofs are hex-encoded 96 bytes: announcement A || response z_s || response z_r

  # --- Happy Path ---

  Scenario: CHALLENGE issues a nonce with TTL for an active client
    When the application executes "2FAPI.CHALLENGE alice-payments"
    Then Redis responds with an array of two bulk strings:
      | Index | Content                             |
      | 0     | challenge_id starting with "ch-"    |
      | 1     | 48-character hex nonce (24 bytes)    |
    And a hash key "2fapi:challenge:<challenge_id>" exists
    And the hash contains field "client_id" = "alice-payments"
    And the hash contains field "nonce" matching the returned nonce
    And the key has a TTL of approximately 120 seconds

  Scenario: VERIFY accepts a valid proof and returns OK
    Given a challenge "ch-alice-001" has been issued for Alice with nonce N
    And Alice has computed a valid Sigma proof binding N via Fiat-Shamir
    When the application executes:
      """
      2FAPI.VERIFY alice-payments ch-alice-001 <proof_hex>
      """
    Then Redis responds with "OK"
    And the challenge key "2fapi:challenge:ch-alice-001" is deleted (consumed)

  Scenario: Challenge is consumed after verification (single-use)
    Given Alice has verified successfully against challenge "ch-alice-001"
    When Alice attempts to verify again with the same challenge:
      """
      2FAPI.VERIFY alice-payments ch-alice-001 <proof_hex>
      """
    Then Redis responds with "DENIED"
    And no challenge key exists for "ch-alice-001"

  # --- Error Path ---

  Scenario: VERIFY rejects an expired challenge
    Given a challenge "ch-alice-002" was issued for Alice
    And the challenge's TTL has expired (EXPIRE triggered by Redis)
    When Alice submits a valid proof for "ch-alice-002"
    Then the challenge key no longer exists in Redis
    And Redis responds with "DENIED"

  Scenario: VERIFY rejects proof for wrong client
    Given a challenge "ch-alice-003" was issued for Alice
    When Bob (a different client) submits a proof for Alice's challenge:
      """
      2FAPI.VERIFY bob-service ch-alice-003 <bob_proof_hex>
      """
    Then the stored client_id "alice-payments" does not match "bob-service"
    And Redis responds with "DENIED"
    And the challenge is consumed (deleted) to prevent further attempts

  Scenario: Replay of a consumed challenge is rejected
    Given challenge "ch-alice-004" was consumed by a previous VERIFY call
    When any client attempts to use "ch-alice-004" again
    Then the challenge key does not exist
    And Redis responds with "DENIED"

  Scenario: DENIED response is indistinguishable across failure modes
    Given the following failure conditions:
      | Condition              | Internal reason              |
      | Expired challenge      | Key evicted by Redis TTL     |
      | Wrong client           | client_id field mismatch     |
      | Invalid proof          | Sigma equation does not hold |
      | Already consumed       | Key deleted by prior VERIFY  |
    When any of these conditions occur during VERIFY
    Then Redis responds with "DENIED" in all cases
    And no additional error detail is provided
    And the response timing does not leak the failure reason

  Scenario: CHALLENGE refuses an unknown client
    When the application executes "2FAPI.CHALLENGE nonexistent-client"
    Then the HGET on "2fapi:client:nonexistent-client" "status" returns nil
    And Redis responds with error "Challenge refused"
```

---

## Feature 4: Client Lifecycle (5 scenarios)

```gherkin
Feature: Client Lifecycle Management via redis-2fapi
  As an administrator
  I want to revoke clients and manage their lifecycle
  So that compromised or decommissioned clients lose access

  Background:
    Given the 2fapi module is loaded in Redis
    And Alice is enrolled with client_id = 'alice-payments' and status = 'active'

  # --- Happy Path ---

  Scenario: REVOKE changes client status to revoked
    When the administrator executes "2FAPI.REVOKE alice-payments"
    Then Redis responds with "OK"
    And HGET "2fapi:client:alice-payments" "status" returns "revoked"

  Scenario: STATUS reflects the revocation
    Given Alice has been revoked
    When the application executes "2FAPI.STATUS alice-payments"
    Then Redis responds with "revoked"

  # --- Error Path ---

  Scenario: Revoked client cannot request a challenge
    Given Alice has been revoked via 2FAPI.REVOKE
    When the application executes "2FAPI.CHALLENGE alice-payments"
    Then Redis responds with error "Challenge refused"
    And the error is indistinguishable from the unknown-client error

  Scenario: Revoked client cannot verify a proof
    Given Alice had a pending challenge "ch-alice-005" before revocation
    And Alice is then revoked via 2FAPI.REVOKE
    When Alice attempts to verify with the pending challenge
    Then the challenge may still exist but the status check fails
    And Redis responds with "DENIED"

  # --- Edge Case ---

  Scenario: Re-enrollment after revocation is refused
    Given Alice has been revoked
    When the application attempts to enroll again:
      """
      2FAPI.ENROLL alice-payments <new_commitment_hex>
      """
    Then Redis responds with error "Client already enrolled"
    And the revoked status is preserved
    And the original commitment is not overwritten
```

---

## Feature 5: Key-Level Access Control (5 scenarios)

```gherkin
Feature: Key-Level Access Control via redis-2fapi
  As an application developer
  I want authenticated clients to access only their own Redis keys
  So that data isolation is enforced at the database layer

  Background:
    Given the 2fapi module is loaded in Redis
    And Alice is enrolled and has successfully verified via 2FAPI.VERIFY
    And Bob is enrolled and has successfully verified on a separate connection
    And the module tracks authenticated client_id per Redis connection
    And key-level ACL maps client_id to permitted key patterns
    And authentication has a TTL after which the session expires

  # --- Happy Path ---

  Scenario: Authenticated client reads its own keys
    Given Alice's connection is authenticated as 'alice-payments'
    And keys matching pattern "app:alice-payments:*" belong to Alice
    When Alice executes "GET app:alice-payments:balance"
    Then the operation is permitted
    And the value is returned normally

  Scenario: Authentication expires after session TTL
    Given Alice authenticated 30 minutes ago
    And the session TTL is configured to 15 minutes
    When Alice attempts to access her keys
    Then the authentication has expired
    And Alice must re-authenticate with a fresh challenge and proof

  # --- Error Path ---

  Scenario: Unauthenticated client is denied access to protected keys
    Given a new Redis connection with no 2FAPI authentication
    When the connection attempts to access "app:alice-payments:balance"
    Then access is denied
    And the error message does not reveal whether the key exists

  Scenario: Cross-client key access is denied
    Given Alice's connection is authenticated as 'alice-payments'
    When Alice attempts to access "app:bob-service:secret"
    Then access is denied
    And Alice can only access keys matching her own client_id prefix

  Scenario: Session is scoped to a single Redis connection
    Given Alice has authenticated on connection A
    And a new connection B is opened by the same application
    When connection B attempts to access Alice's keys without authenticating
    Then access is denied on connection B
    And connection A's authentication does not transfer to connection B
```

---

## TDD Implementation Order

The implementation follows outside-in TDD with baby steps. Each step is a RED-GREEN-REFACTOR cycle.

### Phase 1: Module Skeleton
1. Test that MODULE LOAD succeeds and "MODULE LIST" includes "2fapi"
2. Test that 2FAPI.ENROLL with wrong arity returns WrongArity error
3. Test that 2FAPI.CHALLENGE with wrong arity returns WrongArity error
4. Test that 2FAPI.VERIFY with wrong arity returns WrongArity error
5. Test that 2FAPI.STATUS with wrong arity returns WrongArity error
6. Test that 2FAPI.REVOKE with wrong arity returns WrongArity error

### Phase 2: Client Enrollment
7. Test that 2FAPI.ENROLL with valid hex creates hash key with commitment and status=active
8. Test that 2FAPI.ENROLL rejects invalid hex encoding
9. Test that 2FAPI.ENROLL rejects commitment not exactly 32 bytes
10. Test that 2FAPI.ENROLL rejects non-canonical Ristretto255 point
11. Test that 2FAPI.ENROLL rejects the identity element
12. Test that 2FAPI.STATUS returns "active" for enrolled client
13. Test that 2FAPI.STATUS returns "unknown" for non-existent client
14. Test that 2FAPI.ENROLL refuses duplicate client_id

### Phase 3: Challenge Issuance
15. Test that 2FAPI.CHALLENGE returns [challenge_id, nonce_hex] for active client
16. Test that challenge_id starts with "ch-"
17. Test that a hash key "2fapi:challenge:<id>" is created with client_id and nonce
18. Test that the challenge key has a TTL of ~120 seconds
19. Test that 2FAPI.CHALLENGE returns error for unknown client
20. Test that 2FAPI.CHALLENGE returns error for revoked client

### Phase 4: Proof Verification
21. Test that 2FAPI.VERIFY with invalid hex returns error
22. Test that 2FAPI.VERIFY with wrong proof size returns error
23. Test that 2FAPI.VERIFY deletes the challenge key regardless of outcome
24. Test that 2FAPI.VERIFY returns "DENIED" when challenge key does not exist
25. Test that 2FAPI.VERIFY returns "DENIED" when client_id mismatches
26. Test that 2FAPI.VERIFY builds correct Fiat-Shamir transcript (same format as TypeScript)
27. Test that 2FAPI.VERIFY returns "OK" for a valid proof (integration test with crypto-core)
28. Test that replaying a consumed challenge returns "DENIED"

### Phase 5: Client Lifecycle
29. Test that 2FAPI.REVOKE sets status field to "revoked"
30. Test that 2FAPI.STATUS returns "revoked" after revocation
31. Test that 2FAPI.CHALLENGE returns error for revoked client
32. Test that 2FAPI.ENROLL refuses re-enrollment of a revoked client

### Phase 6: Key-Level Access Control
33. Test that after successful VERIFY, the connection is marked as authenticated
34. Test that an authenticated connection can access keys matching its client_id prefix
35. Test that an unauthenticated connection is denied access to protected keys
36. Test that cross-client key access is denied
37. Test that authentication expires after the configured TTL
38. Test that a new connection does not inherit authentication from another connection
