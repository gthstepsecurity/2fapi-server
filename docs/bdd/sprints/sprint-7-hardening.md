# Sprint 7 — Security Hardening & Performance

> **Goal**: Harden the protocol against advanced attacks, enable batch verification, and validate performance under load.
> **Bounded Context**: Zero-Knowledge Verification (hardening)
> **Scenarios**: 32 | Happy: 4 | Edge: 12 | Error: 16
> **Prerequisites**: Sprint 3 (Core verification must be complete)
> **Key deliverables**: Batch verification, DoS resistance, malleability proof, timing side-channel resistance, transcript integrity, deterministic test vectors, fuzzing harness, cross-platform determinism, performance validation
> **Expert amendments**: Cryptographer (property-based algebraic tests), Security Researcher (dudect methodology for timing), Applied Crypto Engineer (WASM memory zeroization by bytecode inspection), Performance Analyst (warmup + p50/p95/p99 percentile reporting)

---

## Feature: Batch Verification & Performance

```gherkin
Feature: Batch Verification and Performance
  As the authentication server
  I want to verify multiple proofs efficiently and maintain performance under load
  So that high-throughput deployments remain fast and reliable

  Background:
    Given the authentication service is operational

  # --- Happy Path ---

  Scenario: Batch verification of multiple simultaneous proofs
    Given 100 different clients each submit a valid proof simultaneously
    When the server processes all 100 proofs
    Then all 100 verifications succeed
    And each individual invalid proof within a batch is rejected independently
    And the total verification time is less than 100 times the single-proof verification time

  # --- Edge Cases ---

  Scenario: Server maintains verification under 5 milliseconds at 10000 concurrent requests
    Given the server is under load with 10000 concurrent verification requests
    And the benchmark has completed a warmup phase of at least 1000 iterations
    When each proof is verified
    Then the p50 verification latency remains under 2 milliseconds
    And the p95 verification latency remains under 4 milliseconds
    And the p99 verification latency remains under 5 milliseconds
    And no verification is dropped or timed out
    And latency percentiles are reported with 95% confidence intervals

  Scenario: Proof generated in WASM is identical to proof generated natively for same inputs
    Given Alice uses a deterministic random source with seed "test_seed_001"
    And Alice generates a proof using the native Rust implementation
    And Alice generates a proof using the WASM implementation with the same seed
    When the two proofs are compared
    Then they are byte-for-byte identical
    And both verify successfully against Alice's commitment
    And the Fiat-Shamir transcript bytes are identical across both platforms

  # --- Happy Path (performance under stress) ---

  Scenario: Graceful degradation at 50K concurrent verifications
    Given the server is under load with 50000 concurrent verification requests
    And the benchmark has completed a warmup phase of at least 2000 iterations
    When all proofs are processed
    Then all valid proofs are eventually verified (no drops, no crashes, no OOM)
    And the p99 latency may increase but remains under 50 milliseconds
    And the p50 latency remains under 10 milliseconds
    And no process exits with an out-of-memory error
    And latency percentiles are reported at p50, p95, and p99

  Scenario: Memory stability across sustained verification load
    Given the server records its baseline resident memory usage
    And the benchmark has completed a warmup phase of at least 500 iterations
    When the server performs 10000 sequential proof verifications
    Then the resident memory usage does not exceed baseline plus 50 megabytes
    And there is no monotonically increasing memory trend across the 10000 iterations
    And memory measurements are sampled at 1000-iteration intervals

  Scenario: Batch verification with mixed valid and invalid proofs
    Given a batch of 50 proofs where 40 are valid and 10 are deliberately invalid
    When the server processes the entire batch
    Then each of the 40 valid proofs is accepted
    And each of the 10 invalid proofs is rejected
    And no valid proof is affected by the presence of invalid proofs in the batch
    And each proof's result is determined independently
```

## Feature: Malleability & Advanced Attack Resistance

```gherkin
Feature: Malleability and Advanced Attack Resistance
  As the authentication system
  I want to resist advanced cryptographic attacks
  So that even sophisticated adversaries cannot forge or manipulate proofs

  Background:
    Given the authentication service is operational

  # --- Edge Cases ---

  Scenario: Proof with a single bit flipped is rejected (malleability resistance)
    Given Eve captures a valid proof from Alice
    And Eve flips one bit in the proof's response value
    When Eve submits the modified proof
    Then the verification is refused
    And the response is indistinguishable from any other proof failure
    And the attempt is recorded in the audit log

  # --- Error Cases ---

  Scenario: Reflection attack is rejected — server message reflected back to server
    Given Eve captures the challenge message sent by the server to Alice
    And Eve sends this challenge message back to the server as if it were a proof
    When the server processes the reflected message
    Then the message is rejected because it does not conform to the proof format
    And the attempt is recorded in the audit log as suspicious activity
```

## Feature: Timing Side-Channel Resistance

```gherkin
Feature: Timing Side-Channel Resistance
  As the authentication system
  I want all verification paths to execute in constant time
  So that timing measurements cannot reveal information about secrets, clients, or failure reasons

  Background:
    Given the authentication service is operational
    And the timing test harness uses the dudect methodology with at least 10000 samples per class
    And timing measurements use a monotonic high-resolution clock (nanosecond precision)

  # --- Edge Cases ---

  Scenario: Constant-time verification regardless of proof validity
    Given 10000 valid proofs are prepared for timing class A
    And 10000 invalid proofs (wrong response values) are prepared for timing class B
    When both classes are interleaved and submitted to the verifier
    And execution times are collected for each class
    Then the Welch t-test statistic between class A and class B is below the threshold (|t| < 4.5)
    And the verification is deemed constant-time with respect to proof validity
    And the raw timing samples are available for independent statistical analysis

  Scenario: Constant-time commitment lookup regardless of client existence
    Given 10000 requests reference existing client identifiers (timing class A)
    And 10000 requests reference non-existent client identifiers (timing class B)
    And non-existent client lookups use a dummy commitment for constant-time comparison
    When both classes are interleaved and the lookup plus verification is timed
    Then the Welch t-test statistic between class A and class B is below the threshold (|t| < 4.5)
    And an attacker cannot distinguish "unknown client" from "known client, wrong proof"

  Scenario: Constant-time channel binding comparison
    Given 10000 proofs with correct channel binding are prepared (timing class A)
    And 10000 proofs with incorrect channel binding (differing at various byte positions) are prepared (timing class B)
    When both classes are interleaved and submitted to the verifier
    And execution times are collected for each class
    Then the Welch t-test statistic between class A and class B is below the threshold (|t| < 4.5)
    And the comparison uses the subtle crate's constant-time equality function

  # --- Error Cases ---

  Scenario: All error paths take the same observable time as success paths
    Given proofs are prepared for five timing classes:
      | class | description                           |
      | A     | valid proof (success)                 |
      | B     | unknown client identifier              |
      | C     | expired challenge                      |
      | D     | incorrect response values              |
      | E     | wrong channel binding                  |
    And each class contains at least 10000 samples
    When all classes are interleaved and submitted to the verifier
    And execution times are collected per class
    Then no pairwise Welch t-test between any two classes exceeds the threshold (|t| < 4.5)
    And the system is deemed constant-time across all failure modes
```

## Feature: Transcript & Protocol Integrity

```gherkin
Feature: Transcript and Protocol Integrity
  As the authentication system
  I want to ensure the Fiat-Shamir transcript is tamper-proof and session-bound
  So that no manipulation of transcript fields can produce a forgery or cross-session attack

  Background:
    Given the authentication service is operational
    And Alice is registered with a valid commitment

  # --- Error Cases ---

  Scenario: Fiat-Shamir transcript field reordering produces different challenge (injection resistance)
    Given Alice generates a valid proof with transcript fields in canonical order:
      | field            | value                    |
      | domain_tag       | "2FApi-v1.0-Sigma"       |
      | generator_g      | (standard basepoint)     |
      | generator_h      | (hash-derived generator) |
      | commitment       | Alice's commitment C     |
      | announcement     | prover's announcement A  |
      | nonce            | "n_challenge_42"         |
      | channel_binding  | "tls_binding_xyz"        |
    When Eve reorders the transcript fields (e.g., swaps nonce and channel_binding)
    And Eve computes the Fiat-Shamir challenge from the reordered transcript
    Then the resulting challenge is different from Alice's legitimate challenge
    And any proof constructed with the reordered challenge is rejected by the server

  Scenario: Interleaving attack — combining elements from two different sessions is rejected
    Given Alice initiates two authentication sessions S1 and S2 with different nonces
    And Alice generates announcement A1 for session S1 and announcement A2 for session S2
    When Eve constructs a proof using announcement A1 from S1 and response values from S2
    And Eve submits this hybrid proof against either session's challenge
    Then the verification is refused
    And the attempt is recorded in the audit log as suspicious activity

  Scenario: Nonce reuse detection — same announcement seen twice with different challenges triggers alert
    Given Alice submits a proof with announcement A and challenge c1 in session S1
    And Alice (or Eve) submits another proof with the same announcement A but challenge c2 in session S2
    And c1 is not equal to c2
    When the server detects that announcement A has been reused across sessions
    Then a "nonce_reuse_detected" security event is published
    And Alice's client is flagged for investigation
    And the server considers revoking Alice's commitment as a precaution
    And both sessions are invalidated

  Scenario: Proof with manipulated Fiat-Shamir challenge is rejected
    Given Alice generates a valid announcement A and response values (z_s, z_r)
    And Eve intercepts and replaces the challenge c with a different value c_prime
    And Eve adjusts neither z_s nor z_r to match c_prime
    When Eve submits the proof with (A, c_prime, z_s, z_r)
    Then the server recomputes c from the transcript as c_expected = H(tag || g || h || C || A || nonce || binding)
    And c_prime does not match c_expected
    And the verification is refused before the verification equation is checked

  Scenario: Domain separation ensures cross-protocol proof reuse is impossible
    Given Alice generates a valid 2FApi proof with domain tag "2FApi-v1.0-Sigma"
    And a different protocol uses the same curve and generators but domain tag "OtherProto-v1.0"
    When Eve submits Alice's 2FApi proof to the other protocol's verifier
    Then the proof is rejected because the domain separation tag differs
    And when Eve submits a proof from the other protocol to 2FApi's verifier
    Then the proof is also rejected
    And no proof is valid across protocol boundaries regardless of shared parameters
```

## Feature: Deterministic Test Vectors

```gherkin
Feature: Deterministic Test Vectors
  As the development and audit team
  I want deterministic, reproducible test vectors for the entire protocol
  So that implementations can be validated across platforms and over time

  Background:
    Given the cryptographic parameters are the standard 2FApi Ristretto255 generators
    And the domain separation tag is "2FApi-v1.0-Sigma"

  # --- Happy Path ---

  Scenario: Known test vectors produce expected proof bytes
    Given the following fixed inputs:
      | parameter       | hex value                                                          |
      | secret_s        | 0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e80f |
      | blinding_r      | 1122334455667788990011223344556677889900112233445566778899001102 |
      | proof_nonce_k_s | aabbccddeeff00112233445566778899aabbccddeeff00112233445566778809 |
      | proof_nonce_k_r | ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 |
      | challenge_nonce | "test_nonce_vector_001"                                            |
      | channel_binding | "test_binding_vector_001"                                          |
    When the commitment C is computed as g^s * h^r
    And the proof is generated with the given nonces
    Then the commitment bytes match the expected reference value
    And the announcement bytes match the expected reference value
    And the challenge scalar matches the expected reference value
    And the response scalars (z_s, z_r) match the expected reference values
    And the complete serialized proof matches the expected reference bytes

  # --- Edge Cases ---

  Scenario: Cross-platform determinism — WASM proof matches native proof at byte level
    Given the same fixed inputs as the known test vector
    When the proof is generated using the native Rust implementation
    And the proof is generated using the WASM implementation
    Then every byte of both proofs is identical
    And the Fiat-Shamir transcript intermediate hash states are identical
    And both proofs are verified successfully by the native verifier
    And both proofs are verified successfully by the WASM verifier

  Scenario: Round-trip property — generate then verify always succeeds for valid inputs (property-based)
    Given a property-based test generator producing random valid inputs:
      | parameter       | constraint                              |
      | secret_s        | random scalar in [1, group_order - 1]   |
      | blinding_r      | random scalar in [1, group_order - 1]   |
      | challenge_nonce | random 32-byte string                   |
      | channel_binding | random 32-byte string                   |
    When 10000 random input sets are generated
    And for each input set, a commitment is created and a proof is generated and verified
    Then all 10000 verifications succeed (completeness property)
    And this validates the algebraic completeness: for all valid (s, r, k_s, k_r), Verify(Prove(s, r, k_s, k_r)) = true

  Scenario: Invalid inputs property — random bytes as proof never verify (property-based)
    Given a property-based test generator producing:
      | parameter    | constraint                                 |
      | proof_bytes  | random bytes of valid proof length (128 B)  |
      | client_id    | a registered client with a valid commitment |
      | challenge    | a valid pending challenge                   |
    When 10000 random proof byte sequences are submitted for verification
    Then none of the 10000 random proofs verify successfully (soundness property)
    And the probability of accidental verification is bounded by 2^(-128)
```

## Feature: Fuzzing & Input Hardening

```gherkin
Feature: Fuzzing and Input Hardening
  As the authentication system
  I want to safely handle all possible byte sequences as proof input
  So that no crafted input can cause crashes, hangs, or undefined behavior

  Background:
    Given the authentication service is operational
    And the proof parser accepts fixed-length input of 128 bytes

  # --- Error Cases ---

  Scenario: Structured fuzzing — random valid-length proofs cause no crash or hang
    Given a fuzzing harness generates 100000 random 128-byte sequences
    When each sequence is submitted to the proof parser and verifier
    Then no invocation causes a panic, crash, or process abort
    And no invocation hangs for more than 100 milliseconds
    And every invocation returns either a successful verification or a well-formed error
    And the fuzzer achieves at least 90% code coverage of the proof parsing module

  Scenario: Oversized fields within valid-length proof are rejected
    Given a 128-byte proof where the scalar fields contain values exceeding the group order
    When the proof is submitted for verification
    Then the proof is rejected at the deserialization stage
    And the error indicates non-canonical scalar encoding
    And no scalar multiplication is performed

  Scenario: All-zeros proof is rejected (identity point as announcement)
    Given a 128-byte proof consisting entirely of zero bytes
    When the proof is submitted for verification
    Then the proof is rejected because the announcement decodes to the identity point
    And the rejection occurs before the verification equation is evaluated
    And the error is indistinguishable from any other proof failure

  Scenario: All-ones proof (0xFF bytes) is rejected (non-canonical encoding)
    Given a 128-byte proof consisting entirely of 0xFF bytes
    When the proof is submitted for verification
    Then the proof is rejected because the bytes do not represent valid canonical group elements
    And the rejection occurs at the deserialization stage
    And no cryptographic computation is performed on the invalid input
```

## Feature: Denial-of-Service Resistance

```gherkin
Feature: Denial-of-Service Resistance
  As the authentication system
  I want to resist denial-of-service attacks targeting the verification process
  So that legitimate clients are not impacted by attackers flooding with expensive operations

  Background:
    Given the authentication service is operational

  # --- Happy Path (defensive) ---

  Scenario: Server rejects malformed proofs before expensive verification
    Given Eve submits 10000 proofs with invalid encoding within 1 second
    When the server processes each submission
    Then each is rejected at the parsing stage without performing scalar multiplication
    And the server's resources are not significantly impacted
    And legitimate clients continue to be served normally

  # --- Error Cases ---

  Scenario: Rate limiting prevents proof submission flooding per source
    Given Eve submits 1000 proof verification requests from the same source within 10 seconds
    When the rate limiter evaluates the request volume
    Then requests beyond the rate limit are rejected without processing
    And a "rate_limit_exceeded" event is recorded
    And legitimate clients from other sources are unaffected

  Scenario: Large proof payload is rejected before parsing
    Given Eve submits a proof payload that exceeds the maximum allowed size of 1024 bytes
    When the server receives the request
    Then the request is rejected immediately
    And no parsing or verification is attempted

  Scenario: Proof submission with consumed challenge does not trigger expensive verification
    Given Alice's challenge "n_challenge_42" was already consumed by a previous successful verification
    And Eve submits a proof bound to the consumed challenge "n_challenge_42"
    When the server receives the proof
    Then the server detects the challenge is consumed before performing any scalar multiplication
    And the proof is rejected with a "challenge_consumed" error
    And the rejection is as fast as the consumed-challenge lookup (no crypto operations)

  Scenario: Rate limiting is per-client AND per-source-IP
    Given Eve controls 10 different source IP addresses
    And Eve submits requests for client "alice-payment-service" distributed across all 10 IPs
    When the total request volume for client "alice-payment-service" exceeds the per-client rate limit
    Then requests for "alice-payment-service" are throttled regardless of source IP
    And simultaneously, requests from any single IP exceeding the per-IP limit are also throttled
    And both rate limit dimensions are enforced independently
    And "rate_limit_exceeded" events include both the client identifier and source IP

  Scenario: Adaptive rate limiting adjusts threshold based on global load
    Given the server is operating under normal load with a base rate limit of 100 requests per second per client
    When global verification load exceeds 80% of server capacity
    Then the per-client rate limit is reduced proportionally to protect server stability
    And when global load drops below 50% of capacity, rate limits return to baseline
    And rate limit adjustments are logged with the current global load percentage
    And no legitimate client is permanently penalized by temporary load spikes
```

## Feature: WASM Security Validation

```gherkin
Feature: WASM Security Validation
  As the security team
  I want to verify that WASM compilation preserves security properties
  So that browser-based clients have the same security guarantees as native clients

  Background:
    Given the crypto core is compiled to WASM via wasm-bindgen

  # --- Edge Cases ---

  Scenario: WASM memory zeroization is verified by bytecode inspection
    Given the WASM binary is compiled from the crypto core with zeroize enabled
    When the WASM bytecode is inspected for the proof generation function
    Then memory store instructions targeting secret scalar locations are present after the proof is assembled
    And the zeroization stores write zero values to all memory offsets that held secret_s, blinding_r, k_s, and k_r
    And no WASM optimization pass has elided the zeroization stores
    And this is validated by bytecode analysis, not runtime observation alone
```

---

## TDD Implementation Order

### Phase 1: Timing Side-Channel Resistance
1. **RED**: Constant-time verification — dudect with 10K+ samples, Welch t-test |t| < 4.5 (valid vs. invalid proofs)
2. **RED**: Constant-time commitment lookup — dummy lookup for unknown clients, t-test validation
3. **RED**: Constant-time channel binding comparison — subtle crate, t-test validation
4. **RED**: All error paths same observable time — 5-class timing test (success, unknown, expired, wrong proof, wrong binding)

### Phase 2: Transcript & Protocol Integrity
5. **RED**: Fiat-Shamir transcript field reordering → different challenge (injection resistance)
6. **RED**: Interleaving attack — hybrid proof from two sessions → rejection
7. **RED**: Nonce reuse detection — same announcement A with different challenges → alert + revocation consideration
8. **RED**: Manipulated Fiat-Shamir challenge (c_prime != c_expected) → rejection before verification equation
9. **RED**: Domain separation — cross-protocol proof reuse impossible

### Phase 3: Deterministic Test Vectors
10. **RED**: Known test vectors — fixed inputs → expected commitment, announcement, challenge, response bytes
11. **RED**: Cross-platform determinism — WASM == native at byte level including transcript intermediates
12. **RED**: Round-trip property (completeness) — 10K random valid inputs → all verify (property-based)
13. **RED**: Invalid inputs property (soundness) — 10K random byte proofs → none verify (property-based)

### Phase 4: Fuzzing & Input Hardening
14. **RED**: Structured fuzzing — 100K random valid-length proofs → no crash, no hang, always deterministic result
15. **RED**: Oversized scalar fields within valid-length proof → rejected at deserialization
16. **RED**: All-zeros proof → rejected (identity point announcement)
17. **RED**: All-ones proof (0xFF) → rejected (non-canonical encoding)

### Phase 5: Batch Verification & Performance (with warmup + percentile reporting)
18. **RED**: Batch verification — 100 proofs verified efficiently (multi-scalar multiplication)
19. **RED**: Invalid proof in batch rejected independently (mixed valid+invalid batch)
20. **RED**: Performance benchmark — warmup 1000 iterations, then p50 < 2ms, p95 < 4ms, p99 < 5ms at 10K concurrent
21. **RED**: Graceful degradation — 50K concurrent, p99 < 50ms, no OOM, no crash
22. **RED**: Memory stability — 10K verifications, memory stays within baseline + 50MB, no monotonic growth

### Phase 6: DoS Resistance
23. **RED**: Malformed proof rejected before scalar multiplication (parsing stage)
24. **RED**: Rate limiting per source (requests/second threshold)
25. **RED**: Payload size limit enforcement (1024 bytes max)
26. **RED**: Consumed challenge short-circuits before crypto operations
27. **RED**: Rate limiting per-client AND per-source-IP (dual dimension)
28. **RED**: Adaptive rate limiting — threshold adjusts with global load

### Phase 7: WASM & Cross-Platform Security
29. **RED**: WASM memory zeroization verified by bytecode inspection (not runtime only)
30. **RED**: WASM proof byte-for-byte identical to native proof (deterministic seed)

### Phase 8: Algebraic Property Tests (Cryptographer amendment)
31. **RED**: Completeness property — Verify(Prove(valid_inputs)) = true for all valid inputs (10K samples)
32. **RED**: Soundness property — random proof bytes never verify (10K samples, bound 2^-128)
