# Sprint 18 — pg_2fapi Core (PostgreSQL Extension)

> **Goal**: Deliver the pg_2fapi PostgreSQL extension providing ZKP authentication as SQL-callable functions with Row-Level Security integration.
> **Bounded Context**: Cross-cutting (database-native authentication)
> **Scenarios**: 39 | Happy: 17 | Edge: 10 | Error: 12
> **Prerequisites**: Sprint 3 (verification core), Sprint 7 (hardening), crypto-core crate stable
> **Key deliverables**: pgrx-based extension with enroll/challenge/verify/authenticate/current_client functions, RLS integration, audit logging

---

## Feature 1: Extension Installation (5 scenarios)

```gherkin
Feature: pg_2fapi Extension Installation
  As a database administrator
  I want to install pg_2fapi via CREATE EXTENSION
  So that ZKP authentication is available as native PostgreSQL functions

  Background:
    Given a PostgreSQL 15+ server is running
    And the pg_2fapi shared library is available in the PostgreSQL extension directory
    And the pg_2fapi.control file specifies schema "twofapi"

  # --- Happy Path ---

  Scenario: CREATE EXTENSION creates schema and internal tables
    Given the database does not have the pg_2fapi extension installed
    When the administrator executes "CREATE EXTENSION pg_2fapi"
    Then a schema "twofapi" is created
    And a table "twofapi.clients" exists with columns:
      | Column             | Type        | Constraint                                      |
      | client_id          | TEXT        | PRIMARY KEY                                     |
      | commitment         | BYTEA       | NOT NULL, CHECK (length(commitment) = 32)       |
      | status             | TEXT        | NOT NULL, DEFAULT 'active', CHECK IN (active, suspended, revoked) |
      | commitment_version | INTEGER     | NOT NULL, DEFAULT 1                             |
      | created_at         | TIMESTAMPTZ | NOT NULL, DEFAULT now()                         |
      | updated_at         | TIMESTAMPTZ | NOT NULL, DEFAULT now()                         |
    And a table "twofapi.challenges" exists with columns:
      | Column       | Type        | Constraint                                 |
      | challenge_id | TEXT        | PRIMARY KEY                                |
      | client_id    | TEXT        | NOT NULL, REFERENCES twofapi.clients       |
      | nonce        | BYTEA       | NOT NULL                                   |
      | created_at   | TIMESTAMPTZ | NOT NULL, DEFAULT now()                    |
      | expires_at   | TIMESTAMPTZ | NOT NULL                                   |
    And an index "idx_challenges_client" exists on twofapi.challenges(client_id)
    And an index "idx_challenges_expires" exists on twofapi.challenges(expires_at)
    And the following SQL-callable functions are registered:
      | Function                          | Schema  |
      | enroll(text, bytea, bytea)        | twofapi |
      | is_enrolled(text)                 | twofapi |
      | challenge(text)                   | twofapi |
      | cleanup_expired_challenges()      | twofapi |
      | verify(text, text, bytea)         | twofapi |
      | authenticate(text, text, bytea)   | twofapi |
      | current_client()                  | twofapi |
      | is_verified()                     | twofapi |
      | pg_2fapi_version()                | public  |

  Scenario: Extension version check returns correct version
    Given pg_2fapi is installed
    When the administrator executes "SELECT pg_2fapi_version()"
    Then the result is "0.1.0"

  Scenario: Idempotent installation does not error on repeated CREATE EXTENSION
    Given pg_2fapi is already installed in the database
    When the administrator executes "CREATE EXTENSION IF NOT EXISTS pg_2fapi"
    Then no error is raised
    And the existing schema and tables are preserved
    And no data is lost

  Scenario: Uninstall removes all extension objects
    Given pg_2fapi is installed
    And the "twofapi.clients" table contains enrolled clients
    When the administrator executes "DROP EXTENSION pg_2fapi CASCADE"
    Then the schema "twofapi" is dropped
    And all twofapi tables, indexes, and functions are removed
    And no orphan objects remain in the database

  # --- Error Path ---

  Scenario: Installation fails gracefully when shared library is missing
    Given the pg_2fapi.so shared library is not in the PostgreSQL lib directory
    When the administrator executes "CREATE EXTENSION pg_2fapi"
    Then PostgreSQL raises an error indicating the shared library could not be loaded
    And no partial schema or tables are created
```

---

## Feature 2: Client Enrollment (8 scenarios)

```gherkin
Feature: Client Enrollment via pg_2fapi
  As an application developer
  I want to enroll clients with Pedersen commitments directly in PostgreSQL
  So that client identity is bound to the database layer

  Background:
    Given pg_2fapi is installed and operational
    And the public parameters (generators g and h) are loaded from the crypto core
    And commitments are 32-byte compressed Ristretto255 points
    And proofs of possession are 96 bytes (A || z_s || z_r)
    And all cryptographic validation uses the twofapi_crypto_core crate

  # --- Happy Path ---

  Scenario: Enroll a client with a valid commitment and proof of possession
    Given Alice has generated a secret s and blinding factor r
    And Alice has computed her Pedersen commitment C = g^s * h^r
    And Alice has generated a valid proof of possession for C
    When the application executes:
      """sql
      SELECT twofapi.enroll('alice-payments', '\xC0MMIT...'::bytea, '\xPR00F...'::bytea);
      """
    Then the function returns true
    And a row exists in twofapi.clients with client_id = 'alice-payments'
    And the stored commitment matches Alice's commitment C
    And the client status is 'active'
    And created_at is set to the current timestamp

  Scenario: Proof of possession is verified before storing the commitment
    Given Bob has computed a valid commitment C_bob
    And Bob provides a proof of possession that correctly opens C_bob
    When the application enrolls Bob with his commitment and proof
    Then the proof of possession is verified against C_bob using the Sigma equation
    And the Fiat-Shamir transcript binds g, h, C, A, client_id, and domain tag
    And the enrollment succeeds only if the proof verifies

  Scenario: Idempotent re-enrollment with same identifier returns success
    Given Alice is already enrolled with client_id = 'alice-payments' and commitment C
    When the application calls twofapi.enroll('alice-payments', C, valid_proof) again
    Then the function returns true
    And no duplicate row is created (ON CONFLICT DO NOTHING)
    And Alice's existing enrollment is preserved unchanged

  Scenario: Enrollment is recorded in the audit log
    Given the audit logging mechanism is active
    When the application enrolls a new client 'audit-test-client'
    Then a NOTICE-level log entry is emitted containing "Client 'audit-test-client' enrolled successfully"
    And the log entry includes the timestamp of enrollment

  # --- Error Path ---

  Scenario: Enrollment rejects the identity element as commitment
    Given a commitment that encodes the Ristretto255 identity element (all zeros)
    When the application calls twofapi.enroll('mallory', identity_commitment, proof)
    Then PostgreSQL raises an error with message "Commitment must not be the identity element"
    And no row is inserted into twofapi.clients

  Scenario: Enrollment rejects a non-canonical Ristretto255 encoding
    Given a 32-byte value that is not a valid compressed Ristretto255 point
    When the application calls twofapi.enroll('mallory', non_canonical_bytes, proof)
    Then PostgreSQL raises an error with message "Commitment is not a valid Ristretto255 point"
    And no row is inserted into twofapi.clients

  Scenario: Enrollment rejects a commitment with wrong byte length
    Given a commitment that is not exactly 32 bytes
    When the application calls twofapi.enroll('mallory', wrong_length_bytes, proof)
    Then PostgreSQL raises an error with message "Commitment must be exactly 32 bytes"
    And no row is inserted into twofapi.clients

  Scenario: Enrollment rejects a duplicate client_id with different commitment
    Given Alice is already enrolled with client_id = 'alice-payments' and commitment C1
    When the application calls twofapi.enroll('alice-payments', C2, proof_for_C2) where C2 != C1
    Then the ON CONFLICT DO NOTHING clause prevents overwriting
    And the stored commitment remains C1
    And the function returns true (silent no-op)
```

---

## Feature 3: Challenge Issuance (8 scenarios)

```gherkin
Feature: Challenge Issuance via pg_2fapi
  As an application requesting authentication
  I want to obtain a fresh challenge nonce from the database
  So that the client can produce a bound ZK proof

  Background:
    Given pg_2fapi is installed and operational
    And Alice is enrolled with client_id = 'alice-payments' and status = 'active'
    And challenges are stored in twofapi.challenges with a 2-minute TTL
    And nonces are generated from 16 bytes of OS randomness (OsRng)

  # --- Happy Path ---

  Scenario: Issue a challenge with a fresh random nonce
    When the application executes:
      """sql
      SELECT * FROM twofapi.challenge('alice-payments');
      """
    Then the result contains a challenge_id starting with "ch-"
    And the result contains a 32-character hex nonce (16 random bytes)
    And the result contains an expires_at timestamp approximately 2 minutes from now
    And a corresponding row is stored in twofapi.challenges

  Scenario: Issuing a new challenge invalidates the previous one
    Given Alice has an existing pending challenge "ch-previous"
    When the application requests a new challenge for 'alice-payments'
    Then the old challenge "ch-previous" is deleted from twofapi.challenges
    And only the new challenge exists for Alice
    And the new challenge has a fresh nonce unrelated to the previous one

  Scenario: Challenge expires after exactly 2 minutes
    Given a challenge was issued for Alice at time T
    When 2 minutes and 1 second have elapsed since T
    Then the challenge's expires_at is in the past
    And the challenge cannot be used for verification

  Scenario: Cleanup removes all expired challenges
    Given 5 challenges exist in twofapi.challenges
    And 3 of them have expires_at in the past
    When the application executes:
      """sql
      SELECT twofapi.cleanup_expired_challenges();
      """
    Then the function returns 3 (number of deleted challenges)
    And only 2 non-expired challenges remain in the table

  Scenario: Challenge TTL is strictly enforced at verification time
    Given a challenge was issued for Alice 1 minute and 59 seconds ago
    When Alice submits a valid proof before the 2-minute mark
    Then the challenge is still valid and can be consumed
    But if Alice submits the proof 2 seconds later (after the 2-minute mark)
    Then the challenge has expired and verification fails

  # --- Error Path ---

  Scenario: Challenge refused for an unknown client
    When the application executes:
      """sql
      SELECT * FROM twofapi.challenge('nonexistent-client');
      """
    Then PostgreSQL raises an error with message "Challenge refused"
    And the error code is ERRCODE_INSUFFICIENT_PRIVILEGE
    And no challenge is stored in twofapi.challenges

  Scenario: Challenge refused for a revoked client
    Given Bob is enrolled with client_id = 'bob-service' and status = 'revoked'
    When the application requests a challenge for 'bob-service'
    Then PostgreSQL raises an error with message "Challenge refused"
    And the error does not reveal whether the client is revoked or unknown

  Scenario: Challenge refused for a suspended client
    Given Carol is enrolled with client_id = 'carol-api' and status = 'suspended'
    When the application requests a challenge for 'carol-api'
    Then PostgreSQL raises an error with message "Challenge refused"
    And the error message is indistinguishable from the unknown-client case
```

---

## Feature 4: Proof Verification (10 scenarios)

```gherkin
Feature: Zero-Knowledge Proof Verification via pg_2fapi
  As the database authentication layer
  I want to verify Sigma proofs against stored commitments
  So that only clients who know their secret can authenticate

  Background:
    Given pg_2fapi is installed and operational
    And Alice is enrolled with client_id = 'alice-payments', commitment C, and status = 'active'
    And a valid challenge "ch-alice-001" has been issued for Alice with nonce N
    And the challenge has not yet expired
    And the proof format is 96 bytes: announcement A (32) || response z_s (32) || response z_r (32)
    And the Fiat-Shamir transcript format is:
      | Field           | Content                        |
      | tag             | "2FApi-v1.0-Sigma"             |
      | g               | Generator G (32 bytes)         |
      | h               | Generator H (32 bytes)         |
      | commitment      | Client's commitment C          |
      | announcement    | Proof announcement A           |
      | client_id       | Client identifier (UTF-8)      |
      | nonce           | Challenge nonce N              |
      | channel_binding | Context-specific binding       |
    And each field is length-prefixed with a 4-byte big-endian length

  # --- Happy Path ---

  Scenario: Valid proof is accepted and challenge is consumed
    Given Alice has computed a valid Sigma proof binding nonce N:
      | Component | Description                        |
      | A         | Commitment to random k: g^k_s * h^k_r |
      | c         | Fiat-Shamir challenge scalar       |
      | z_s       | k_s + c * s                        |
      | z_r       | k_r + c * r                        |
    When the application executes:
      """sql
      SELECT twofapi.verify('alice-payments', 'ch-alice-001', proof_bytes);
      """
    Then the function returns true
    And the challenge "ch-alice-001" is deleted from twofapi.challenges (consumed)
    And the verification equation g^z_s * h^z_r == A + c*C holds

  Scenario: Challenge is consumed atomically regardless of proof outcome
    Given Alice provides an invalid proof for challenge "ch-alice-001"
    When the application calls twofapi.verify('alice-payments', 'ch-alice-001', bad_proof)
    Then the function returns false
    And the challenge "ch-alice-001" is deleted from twofapi.challenges
    And no subsequent verification attempt can reuse "ch-alice-001"

  Scenario: Verification result is logged for audit
    Given Alice submits a valid proof
    When verification succeeds
    Then a NOTICE-level log entry is emitted
    And the log entry does not contain the proof bytes or commitment

  # --- Error Path ---

  Scenario: Wrong channel binding is rejected
    Given Alice's proof was computed with channel_binding = "tls-exporter-data-xyz"
    But the server rebuilds the transcript with channel_binding = "" (empty)
    When verification is performed
    Then the Fiat-Shamir challenge scalar differs
    And the verification equation fails
    And the function returns false

  Scenario: Wrong client for a given challenge is rejected
    Given the challenge "ch-alice-001" was issued for Alice
    When Bob (a different enrolled client) calls:
      """sql
      SELECT twofapi.verify('bob-service', 'ch-alice-001', bob_proof);
      """
    Then the challenge lookup fails (client_id mismatch in DELETE ... WHERE)
    And the function returns false
    And the challenge is not consumed (it remains available for Alice)

  Scenario: Expired challenge is rejected
    Given the challenge "ch-alice-001" was issued 3 minutes ago (past the 2-minute TTL)
    When Alice submits a valid proof for "ch-alice-001"
    Then the DELETE ... WHERE expires_at > now() clause matches no rows
    And the function returns false

  Scenario: Non-canonical proof encoding is rejected
    Given a proof where the announcement A is not a valid Ristretto255 point
    When verification is attempted
    Then the canonical encoding check fails
    And the function returns false without performing the Sigma equation

  Scenario: Identity element as announcement is rejected
    Given a proof where the announcement A is the identity element
    When verification is attempted
    Then the identity check fails
    And the function returns false

  Scenario: Error responses are indistinguishable
    Given the following failure conditions:
      | Condition              | Internal reason              |
      | Unknown challenge      | Challenge ID not found       |
      | Expired challenge      | TTL exceeded                 |
      | Wrong client           | client_id mismatch           |
      | Invalid proof encoding | Non-canonical point          |
      | Bad proof              | Equation does not hold       |
    When any of these conditions occur
    Then the function returns false in all cases
    And no error detail distinguishes one failure from another
    And the NOTICE log does not leak the specific failure reason to the client

  Scenario: Non-canonical scalar responses are rejected
    Given a proof where z_s or z_r is not a canonical Ristretto255 scalar
    When verification is attempted
    Then the canonical scalar check fails
    And the function returns false
```

---

## Feature 5: Session & RLS Integration (8 scenarios)

```gherkin
Feature: Session Management and Row-Level Security Integration
  As an application developer
  I want successful ZKP verification to establish a database session
  So that Row-Level Security policies can enforce per-client data isolation

  Background:
    Given pg_2fapi is installed and operational
    And Alice is enrolled with client_id = 'alice-payments' and status = 'active'
    And Bob is enrolled with client_id = 'bob-service' and status = 'active'
    And a table "invoices" exists with columns (id, client_id, amount)
    And RLS is enabled on "invoices" with policy:
      """sql
      CREATE POLICY zkp_access ON invoices
        USING (client_id = twofapi.current_client());
      """
    And the session GUC variables are:
      | Variable                      | Purpose                        |
      | twofapi.current_client_id     | Authenticated client identifier |
      | twofapi.session_verified      | Boolean verification flag       |
      | twofapi.session_verified_at   | Timestamp of verification       |

  # --- Happy Path ---

  Scenario: authenticate() sets session GUC variables on successful proof
    Given a valid challenge "ch-alice-001" exists for Alice
    And Alice has a valid proof for this challenge
    When the application executes:
      """sql
      SELECT twofapi.authenticate('alice-payments', 'ch-alice-001', proof_bytes);
      """
    Then the function returns true
    And current_setting('twofapi.current_client_id', true) = 'alice-payments'
    And current_setting('twofapi.session_verified', true) = 'true'
    And current_setting('twofapi.session_verified_at', true) is a valid ISO 8601 timestamp

  Scenario: current_client() returns the authenticated client identifier
    Given Alice has authenticated via twofapi.authenticate()
    When the application executes "SELECT twofapi.current_client()"
    Then the result is 'alice-payments'

  Scenario: current_client() returns NULL when no client is authenticated
    Given no twofapi.authenticate() call has been made in this transaction
    When the application executes "SELECT twofapi.current_client()"
    Then the result is NULL

  Scenario: RLS filters rows by authenticated client
    Given the invoices table contains:
      | id | client_id       | amount |
      | 1  | alice-payments  | 100.00 |
      | 2  | bob-service     | 250.00 |
      | 3  | alice-payments  | 75.50  |
    And Alice has authenticated via twofapi.authenticate()
    When Alice executes "SELECT * FROM invoices"
    Then only rows with client_id = 'alice-payments' are returned (ids 1 and 3)
    And Bob's row (id 2) is not visible

  Scenario: Multiple clients are isolated by RLS
    Given Alice has authenticated and sees only her invoices
    And in a separate transaction, Bob authenticates
    When Bob executes "SELECT * FROM invoices"
    Then Bob sees only rows with client_id = 'bob-service' (id 2)
    And Alice's rows (ids 1 and 3) are not visible to Bob

  Scenario: Session is scoped to the current transaction (SET LOCAL)
    Given Alice has authenticated via twofapi.authenticate()
    And the GUC variables are set with SET LOCAL
    When the current transaction is committed
    And a new transaction begins
    Then twofapi.current_client() returns NULL
    And twofapi.is_verified() returns false
    And the session variables are reset

  Scenario: Session is cleared on client disconnect
    Given Alice has authenticated in a session
    When Alice's database connection is closed
    And a new connection is established
    Then twofapi.current_client() returns NULL on the new connection
    And no session state leaks between connections

  # --- Edge Case ---

  Scenario: authenticate() returns false and does not set session on failed proof
    Given a valid challenge "ch-alice-002" exists for Alice
    And Alice provides an invalid proof
    When the application calls twofapi.authenticate('alice-payments', 'ch-alice-002', bad_proof)
    Then the function returns false
    And twofapi.current_client() still returns NULL
    And twofapi.is_verified() returns false
    And no GUC variables are modified
```

---

## TDD Implementation Order

The implementation follows outside-in TDD with baby steps. Each step is a RED-GREEN-REFACTOR cycle.

### Phase 1: Extension Skeleton
1. Test that `CREATE EXTENSION pg_2fapi` creates the `twofapi` schema
2. Test that `pg_2fapi_version()` returns "0.1.0"
3. Test that `twofapi.clients` table exists with correct columns and constraints
4. Test that `twofapi.challenges` table exists with correct columns and constraints
5. Test that indexes are created on challenges table

### Phase 2: Client Enrollment
6. Test that `twofapi.enroll()` accepts a valid 32-byte commitment and 96-byte proof, returns true
7. Test that `twofapi.enroll()` rejects commitments that are not 32 bytes
8. Test that `twofapi.enroll()` rejects non-canonical Ristretto255 encodings
9. Test that `twofapi.enroll()` rejects the identity element
10. Test that `twofapi.enroll()` stores client with status = 'active'
11. Test that `twofapi.enroll()` is idempotent for same client_id (ON CONFLICT DO NOTHING)
12. Test that `twofapi.is_enrolled()` returns true for active clients, false otherwise

### Phase 3: Challenge Issuance
13. Test that `twofapi.challenge()` returns (challenge_id, nonce, expires_at) for active client
14. Test that challenge_id starts with "ch-"
15. Test that nonce is 32 hex chars (16 random bytes)
16. Test that expires_at is ~2 minutes from now
17. Test that requesting a new challenge deletes the previous one for the same client
18. Test that `twofapi.challenge()` raises error for unknown client
19. Test that `twofapi.challenge()` raises error for revoked client (same error message)
20. Test that `twofapi.cleanup_expired_challenges()` removes expired rows

### Phase 4: Proof Verification
21. Test that `twofapi.verify()` returns false for wrong proof size (!= 96 bytes)
22. Test that `twofapi.verify()` deletes the challenge row atomically (consumed)
23. Test that `twofapi.verify()` returns false for unknown challenge_id
24. Test that `twofapi.verify()` returns false for expired challenge
25. Test that `twofapi.verify()` returns false for mismatched client_id
26. Test that `twofapi.verify()` rejects non-canonical announcement point
27. Test that `twofapi.verify()` rejects identity element as announcement
28. Test that `twofapi.verify()` rejects non-canonical scalar responses
29. Test that `twofapi.verify()` builds the correct Fiat-Shamir transcript
30. Test that `twofapi.verify()` returns true for a valid proof (integration test with crypto-core)

### Phase 5: Session & RLS
31. Test that `twofapi.authenticate()` calls verify and sets GUC on success
32. Test that `twofapi.authenticate()` does not set GUC on failure
33. Test that `twofapi.current_client()` returns the client_id set by authenticate
34. Test that `twofapi.current_client()` returns NULL when no session is active
35. Test that `twofapi.is_verified()` returns true after authenticate, false otherwise
36. Test that SET LOCAL scoping resets GUC after transaction commit
37. Test that RLS policy using `twofapi.current_client()` filters rows correctly
38. Test that two clients in separate transactions are isolated by RLS
39. Test that a new connection has no session state

### Phase 6: Audit & Edge Cases
40. Test that enrollment emits a NOTICE log
41. Test that challenge issuance emits a NOTICE log
42. Test that DROP EXTENSION CASCADE removes all objects cleanly
43. Test that CREATE EXTENSION IF NOT EXISTS is idempotent
