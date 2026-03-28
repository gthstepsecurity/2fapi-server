# Sprint 20 — Extension Hardening & Testing

> **Goal**: Harden pg_2fapi and redis-2fapi against security threats, validate performance targets, and ensure cross-platform consistency with the TypeScript server.
> **Bounded Context**: Cross-cutting (security & performance)
> **Scenarios**: 24 | Happy: 8 | Edge: 8 | Error: 8
> **Prerequisites**: Sprint 18 (pg_2fapi core), Sprint 19 (redis-2fapi core)
> **Key deliverables**: Timing-safe verification, SPI injection prevention, memory cleanup, performance benchmarks, transcript compatibility

---

## Feature 1: PostgreSQL Security Hardening (8 scenarios)

```gherkin
Feature: PostgreSQL Extension Security Hardening
  As a security engineer
  I want pg_2fapi to be resistant to injection, timing, and privilege escalation attacks
  So that the database-native authentication layer cannot be subverted

  Background:
    Given pg_2fapi is installed and operational
    And the extension uses pgrx SPI (Server Programming Interface) for all SQL execution
    And the twofapi_crypto_core crate provides constant-time operations via the "subtle" crate
    And the "zeroize" crate is used for clearing sensitive memory
    And internal tables are in the "twofapi" schema

  # --- Security: Injection Prevention ---

  Scenario: SPI queries use parameterized statements to prevent SQL injection
    Given a malicious client_id containing SQL injection payload:
      | Payload                                    |
      | alice'; DROP TABLE twofapi.clients; --     |
      | ' OR '1'='1                                |
      | alice-payments\x00'; DELETE FROM clients-- |
    When the payload is passed to twofapi.enroll(), twofapi.challenge(), or twofapi.verify()
    Then the SPI parameterized query treats the payload as a literal string value
    And no SQL injection occurs
    And the twofapi.clients table is unmodified
    And the function either succeeds (treating payload as a client_id) or fails with a validation error

  Scenario: Internal tables are protected with REVOKE ALL
    Given pg_2fapi has been installed
    When a non-superuser application role attempts:
      """sql
      INSERT INTO twofapi.clients VALUES ('hacker', '\x00'::bytea, 'active', 1, now(), now());
      DELETE FROM twofapi.challenges;
      UPDATE twofapi.clients SET status = 'active' WHERE client_id = 'revoked-client';
      """
    Then all direct DML statements are denied with insufficient privilege
    And data modification is only possible through the twofapi.* functions
    And the functions execute with SECURITY DEFINER privileges

  Scenario: GUC variable manipulation is rejected for unprivileged roles
    Given a non-superuser connection
    When the user attempts to set session variables directly:
      """sql
      SET LOCAL twofapi.current_client_id = 'attacker';
      SET LOCAL twofapi.session_verified = 'true';
      """
    Then the SET command is denied or the GUC context prevents override
    And twofapi.current_client() does not return 'attacker'
    And only twofapi.authenticate() can legitimately set these variables

  # --- Security: Timing Safety ---

  Scenario: Proof verification executes in constant time via Rust crypto
    Given two proofs for Alice: one valid and one invalid (differing only in z_s)
    When each proof is verified 1000 times against the same commitment and challenge
    Then the mean verification time differs by less than 5% between valid and invalid proofs
    And the crypto_core::verify_equation_raw function uses subtle::ConstantTimeEq internally
    And no early-return optimization leaks information about which byte failed

  Scenario: Constant-time comparison is used for all secret-dependent branches
    Given the verify() function in verify.rs
    When the code path is analyzed
    Then the Sigma equation verification uses crypto::verify_equation_raw (constant-time)
    And nonce comparison is not exposed (consumed atomically via SQL DELETE)
    And client_id matching is performed in the SQL WHERE clause (not in Rust)

  # --- Security: Concurrency & Atomicity ---

  Scenario: Concurrent verification attempts for the same challenge are serialized
    Given a challenge "ch-alice-001" exists for Alice
    When two concurrent transactions attempt to verify with the same challenge simultaneously
    Then only one transaction successfully consumes the challenge (DELETE ... RETURNING)
    And the other transaction gets NULL from the RETURNING clause
    And the second verification attempt returns false
    And no race condition allows double-use of the challenge

  # --- Security: Memory Safety ---

  Scenario: Sensitive memory is cleared after proof verification
    Given a proof has been submitted for verification
    When the verify() function completes (success or failure)
    Then the proof_bytes buffer is eligible for cleanup
    And the reconstructed challenge scalar is not retained in memory
    And the Rust ownership model ensures no dangling references to proof data
    And the pgrx palloc context frees memory at transaction end

  Scenario: Internal function build_transcript does not leak via return value
    Given the build_transcript function constructs the Fiat-Shamir transcript
    When the transcript is used to compute the challenge scalar
    Then the transcript Vec is consumed by hash_transcript_bytes
    And the challenge scalar is used only for the Sigma equation check
    And no intermediate cryptographic values are logged or stored in SQL tables
```

---

## Feature 2: Redis Security Hardening (6 scenarios)

```gherkin
Feature: Redis Module Security Hardening
  As a security engineer
  I want redis-2fapi to be resistant to injection, timing, and memory attacks
  So that the Redis authentication layer cannot be subverted

  Background:
    Given the 2fapi module is loaded in Redis
    And the module uses the twofapi_crypto_core crate for all cryptographic operations
    And Redis commands are parsed via NextArg with strict arity checks
    And all hex decoding uses the hex crate with explicit error handling

  # --- Security: Injection Prevention ---

  Scenario: Command injection via malicious client_id is prevented
    Given a malicious client_id containing:
      | Payload                                   |
      | alice\r\nDEL 2fapi:client:alice-payments  |
      | alice-payments\x00FLUSHALL                |
      | ../../../etc/passwd                       |
    When the payload is used in any 2FAPI command
    Then the client_id is treated as a literal key component
    And no Redis protocol injection occurs
    And key names are built as "2fapi:client:<client_id>" without interpretation

  # --- Security: Timing Safety ---

  Scenario: VERIFY executes in constant time regardless of failure point
    Given two verification attempts:
      | Attempt | Condition                    |
      | A       | Valid proof, correct client   |
      | B       | Invalid proof, correct client |
    When each attempt is executed 1000 times
    Then the response time distribution overlaps significantly
    And the crypto verification step dominates execution time
    And no timing side-channel reveals whether the proof was close to valid

  # --- Security: Memory Safety ---

  Scenario: Proof bytes are not retained after verification
    Given a proof has been submitted via 2FAPI.VERIFY
    When the verify_cmd function completes
    Then the proof Vec<u8> is dropped by Rust's ownership system
    And the commitment bytes retrieved from Redis are dropped
    And the transcript Vec is consumed by hash computation
    And no heap-allocated secret survives beyond the command handler

  Scenario: Large payload rejection prevents memory exhaustion
    Given a client sends an extremely long proof_hex string (> 1MB)
    When the hex::decode processes the input
    Then the decoded length check (96 bytes) rejects the proof immediately
    And Redis memory is not exhausted by the oversized input
    And the module does not crash or enter an undefined state

  # --- Security: Concurrency ---

  Scenario: Concurrent VERIFY on the same challenge is safe
    Given a challenge "ch-alice-001" exists for Alice
    When two Redis clients on separate connections issue VERIFY simultaneously
    Then Redis single-threaded execution model serializes the commands
    And the first VERIFY consumes the challenge (HGET + DEL)
    And the second VERIFY finds no challenge key and returns "DENIED"
    And no race condition is possible due to Redis's atomic command execution

  Scenario: Module handles rapid enrollment-revoke-challenge sequences safely
    Given a burst of commands in rapid succession:
      | Order | Command                                  |
      | 1     | 2FAPI.ENROLL rapid-client <commitment>   |
      | 2     | 2FAPI.CHALLENGE rapid-client             |
      | 3     | 2FAPI.REVOKE rapid-client                |
      | 4     | 2FAPI.CHALLENGE rapid-client             |
    When Redis processes these sequentially
    Then command 1 succeeds (enrolled)
    And command 2 succeeds (challenge issued)
    And command 3 succeeds (revoked)
    And command 4 fails with "Challenge refused" (status is revoked)
    And no inconsistent state results from the rapid sequence
```

---

## Feature 3: Performance Validation (6 scenarios)

```gherkin
Feature: Extension Performance Targets
  As a system architect
  I want both extensions to meet strict latency and throughput targets
  So that ZKP authentication does not become a bottleneck

  Background:
    Given pg_2fapi is installed on a PostgreSQL 15+ server
    And redis-2fapi is loaded on a Redis 7.0+ server
    And the test environment has at least 4 CPU cores and 8GB RAM
    And the crypto-core crate is compiled in release mode with optimizations
    And all benchmarks are run with a warm cache (100 warm-up iterations before measurement)

  # --- Performance: PostgreSQL ---

  Scenario: PostgreSQL proof verification completes in under 5ms
    Given Alice is enrolled with a valid commitment
    And a fresh challenge has been issued
    And a valid proof has been precomputed
    When twofapi.verify() is called 1000 times (each with a fresh challenge)
    Then the p99 latency is below 5ms
    And the median latency is below 3ms
    And the Ristretto255 scalar multiplication dominates the execution time

  Scenario: 1000 concurrent PostgreSQL verifications complete without deadlock
    Given 1000 clients are enrolled with unique commitments
    And each client has a pending challenge
    When 1000 concurrent connections each call twofapi.verify() simultaneously
    Then all 1000 verifications complete within 10 seconds total
    And no deadlocks are detected (pg_stat_activity shows no waiting)
    And the challenge table has 0 rows remaining (all consumed)

  Scenario: Batch enrollment operations maintain throughput
    Given 10000 enrollment requests are prepared with valid commitments
    When they are executed sequentially via twofapi.enroll()
    Then all 10000 enrollments complete within 30 seconds
    And the twofapi.clients table contains 10000 rows
    And no constraint violation errors occur

  # --- Performance: Redis ---

  Scenario: Redis proof verification completes in under 1ms
    Given Alice is enrolled with a valid commitment
    And a fresh challenge has been issued
    And a valid proof has been precomputed as hex
    When 2FAPI.VERIFY is called 1000 times (each with a fresh challenge)
    Then the p99 latency is below 1ms
    And the median latency is below 500 microseconds
    And the crypto verification dominates the execution time (not Redis I/O)

  Scenario: Redis pipeline compatibility with 2FAPI commands
    Given a Redis client using PIPELINE mode
    When the client pipelines 100 2FAPI.CHALLENGE commands for 100 different clients
    Then all 100 responses are returned in a single round-trip
    And each response contains a valid [challenge_id, nonce_hex] array
    And total pipeline execution time is under 50ms

  # --- Performance: Cross-Platform ---

  Scenario: Verification latency ratio between PG and Redis is consistent
    Given identical commitments, challenges, and proofs for both platforms
    When 1000 verifications are performed on each platform
    Then Redis p99 is at least 3x faster than PostgreSQL p99
    And the crypto computation time is identical (same crate, same code)
    And the difference is attributable to PostgreSQL SPI overhead vs Redis in-memory access
```

---

## Feature 4: Cross-Platform Consistency (4 scenarios)

```gherkin
Feature: Cross-Platform Transcript and Proof Consistency
  As a protocol designer
  I want proofs generated for the TypeScript server to also verify in pg_2fapi and redis-2fapi
  So that clients can authenticate against any 2FApi-compatible verifier

  Background:
    Given the TypeScript server, pg_2fapi, and redis-2fapi all use twofapi_crypto_core
    And the Fiat-Shamir transcript format is length-prefixed with tag "2FApi-v1.0-Sigma"
    And the transcript field order is: tag, g, h, commitment, announcement, client_id, nonce, channel_binding
    And each field is prefixed with a 4-byte big-endian length
    And the hash function for the transcript is SHA-512 reduced to a Ristretto255 scalar

  Scenario: Same commitment produces identical bytes across all platforms
    Given a secret s and blinding factor r
    When the commitment C = g^s * h^r is computed by:
      | Platform           | Implementation            |
      | TypeScript (WASM)  | twofapi-crypto-core WASM  |
      | pg_2fapi (pgrx)    | twofapi-crypto-core       |
      | redis-2fapi        | twofapi-crypto-core       |
    Then C is byte-identical across all three platforms
    And the compressed Ristretto255 encoding is canonical in all cases

  Scenario: Same proof format is accepted by all verifiers
    Given a proof generated by the TypeScript WASM client:
      | Field        | Size     | Encoding                   |
      | announcement | 32 bytes | Compressed Ristretto255    |
      | z_s          | 32 bytes | Little-endian scalar       |
      | z_r          | 32 bytes | Little-endian scalar       |
    When the same 96-byte proof is submitted to:
      | Verifier                      |
      | TypeScript server verify()    |
      | twofapi.verify() in PG        |
      | 2FAPI.VERIFY in Redis         |
    Then all three verifiers accept the proof (given matching commitment and nonce)
    And all three verifiers reject a mutated proof identically

  Scenario: Transcript format matches between Rust and TypeScript implementations
    Given the following transcript inputs:
      | Field           | Value (hex)                                      |
      | tag             | "2FApi-v1.0-Sigma" (UTF-8 bytes)                 |
      | g               | (Ristretto255 basepoint compressed)              |
      | h               | (Hash-to-point derived generator)                |
      | commitment      | (32-byte test commitment)                        |
      | announcement    | (32-byte test announcement)                      |
      | client_id       | "test-client" (UTF-8 bytes)                      |
      | nonce           | (24-byte test nonce)                              |
      | channel_binding | (empty)                                           |
    When the transcript is serialized by:
      | Implementation                              |
      | verify.rs build_transcript (pg_2fapi)       |
      | redis lib.rs write_field loop               |
      | TypeScript buildFiatShamirTranscript()       |
    Then the serialized transcript bytes are identical across all implementations
    And the resulting challenge scalar c = H(transcript) is identical

  Scenario: Channel binding field is consistently empty for Redis and populated for TLS contexts
    Given a verification without TLS (Redis, non-TLS PostgreSQL)
    When the transcript is built
    Then the channel_binding field is empty (0-length prefix + no data)
    And the transcript remains valid and produces a deterministic challenge scalar
    And a proof bound with non-empty channel_binding will fail verification (mismatched transcript)
```

---

## TDD Implementation Order

The implementation follows outside-in TDD with baby steps. Each step is a RED-GREEN-REFACTOR cycle.

### Phase 1: PostgreSQL Security
1. Test that SPI queries with SQL injection payloads in client_id do not execute injected SQL
2. Test that direct INSERT into twofapi.clients by non-superuser is denied
3. Test that direct DELETE from twofapi.challenges by non-superuser is denied
4. Test that direct UPDATE on twofapi.clients by non-superuser is denied
5. Test that SET LOCAL twofapi.current_client_id by non-superuser has no effect on current_client()
6. Test that verify() timing is constant regardless of valid/invalid proof (statistical test)
7. Test that concurrent verify() on same challenge allows only one to succeed
8. Test that build_transcript output does not appear in pg_stat_statements or logs

### Phase 2: Redis Security
9. Test that client_id with embedded Redis protocol characters is treated as literal key component
10. Test that 2FAPI.VERIFY timing is statistically indistinguishable for valid/invalid proofs
11. Test that a > 1MB proof_hex input is rejected without memory exhaustion
12. Test that concurrent VERIFY on same challenge is serialized by Redis single-thread model
13. Test that rapid enroll-revoke-challenge sequence produces consistent state
14. Test that no heap-allocated proof data survives after command handler returns

### Phase 3: PostgreSQL Performance
15. Test that twofapi.verify() p99 < 5ms over 1000 iterations
16. Test that twofapi.verify() median < 3ms
17. Test that 1000 concurrent verifications complete without deadlock within 10s
18. Test that 10000 sequential enrollments complete within 30s

### Phase 4: Redis Performance
19. Test that 2FAPI.VERIFY p99 < 1ms over 1000 iterations
20. Test that 2FAPI.VERIFY median < 500us
21. Test that 100 pipelined CHALLENGE commands complete within 50ms
22. Test that Redis verification is at least 3x faster than PostgreSQL verification

### Phase 5: Cross-Platform Consistency
23. Test that commitment bytes from WASM, pg_2fapi, and redis-2fapi are identical for same (s, r)
24. Test that a proof from TypeScript WASM verifies in pg_2fapi
25. Test that a proof from TypeScript WASM verifies in redis-2fapi
26. Test that build_transcript output is byte-identical across all three implementations
27. Test that empty channel_binding produces the same transcript on all platforms
28. Test that non-empty channel_binding causes verification failure when verifier uses empty
