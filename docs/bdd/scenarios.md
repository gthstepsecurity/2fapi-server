# BDD Scenarios — 2FApi

> Generated from client spec on 2026-03-18
> Source: direct input — "2FA between client and server for API call validation with zkProof"
> Security posture: **Maximum** — all hypotheses favor the strictest security option
> Expert review: **7 domain experts** consulted, **23 amendments** integrated

## Summary

| Bounded Context              | Features | Scenarios | Happy | Edge | Error |
|-----------------------------|----------|-----------|-------|------|-------|
| Client Registration         | 3        | 24        | 5     | 8    | 11    |
| Authentication Challenge    | 3        | 21        | 4     | 7    | 10    |
| Zero-Knowledge Verification | 4        | 33        | 5     | 13   | 15    |
| API Access Control          | 2        | 17        | 4     | 6    | 7     |
| Security Monitoring         | 3        | 19        | 5     | 7    | 7     |
| **Total**                   | **15**   | **114**   | **23**| **41**| **50**|

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | Client application developer | Prove her identity to access protected resources without revealing secrets |
| Bob | Server administrator | Ensure only legitimate, registered clients access the resources |
| Eve | Malicious actor | Gain unauthorized access, steal secrets, or disrupt the service |
| System Clock | Time-based trigger | Expire stale challenges, tokens, and lockouts |
| Audit Logger | System component | Record every security-relevant event for forensic analysis |

## Bounded Contexts

| Context | Ubiquitous Language (key terms) |
|---------|-------------------------------|
| Client Registration | enrollment, commitment, secret, blinding factor, public parameters, registered client, revoked client, proof of possession |
| Authentication Challenge | challenge, nonce, credential verification, authentication request, expiry, session, channel binding, protocol version |
| Zero-Knowledge Verification | proof, witness, verification, commitment opening, prover, verifier, transcript, domain separation, announcement, batch verification |
| API Access Control | access token, authenticated session, protected resource, token lifetime, audience, scope, step-up |
| Security Monitoring | failed attempt, lockout, rate limit, audit trail, suspicious activity, alert, retention, anomaly |

## Hypotheses (Security-Hardened)

> These assumptions were made where the spec was silent or ambiguous.
> All favor the **strictest security option**.
> **Review and validate before proceeding.**

1. **H1** — Factor 1 is a client identifier paired with a cryptographic credential (not a simple password). Factor 2 is a zero-knowledge proof of commitment opening. Per IAM terminology: factor 1 = "credential verification", factor 2 = "proof verification".
2. **H2** — The protocol is non-interactive: the client generates the proof locally using the Fiat-Shamir transform with a **domain-separated** transcript including the server-issued nonce.
3. **H3** — The commitment is a Pedersen commitment C = g^s · h^r over Ristretto255, where s is the client's secret (random scalar) and r is the blinding factor.
4. **H4** — Challenges expire after **2 minutes** (strict — minimizes the replay window). Expiry is **strictly less than** the TTL (< 2min, not <=).
5. **H5** — After **3 consecutive failed attempts**, the client is locked out for **60 minutes** (strict — slows brute-force significantly). The client is **notified of the lockout** (per NIST SP 800-63B AAL2 requirement) but the remaining duration is not disclosed.
6. **H6** — Access tokens have a maximum lifetime of **15 minutes** and cannot be renewed — the client must re-authenticate. Tokens are **audience-restricted** to a specific service.
7. **H7** — Every authentication event (success, failure, lockout, revocation) is recorded in an immutable audit log. Retention: **minimum 12 months** (SOC2), **5 years** for regulated sectors (fintech, healthcare).
8. **H8** — If the verification service is unavailable, all authentication requests are **rejected** — no fallback, no degradation.
9. **H9** — Revocation is **immediate**: all active tokens and pending challenges for the revoked client are invalidated instantly.
10. **H10** — The client's secret is a cryptographically random scalar generated exclusively on the client side and **never transmitted** to the server.
11. **H11** — The proof transcript includes a **channel binding** value derived from the TLS session, preventing proof forwarding across connections.
12. **H12** — Only **one concurrent authentication session** is allowed per client. A new challenge request invalidates any pending challenge for that client.
13. **H13** — Commitment rotation requires the client to prove knowledge of the current commitment before registering a new one (authenticated rotation).
14. **H14** — Error responses for "unknown client" and "invalid proof" are **indistinguishable** — preventing client enumeration.
15. **H15** — All cryptographic operations are **constant-time** — no timing oracle is acceptable.
16. **H16** — The Fiat-Shamir transcript includes a **domain separation tag** unique to 2FApi, preventing cross-protocol proof acceptance.
17. **H17** — The public parameters (generators g and h) are generated via **hash-to-curve with a public seed**, making them deterministically verifiable by any party.
18. **H18** — Enrollment requires a **proof of possession** of the commitment opening, preventing an attacker from registering a stolen commitment.
19. **H19** — Nonce uniqueness is guaranteed by combining a **CSPRNG output** with a **monotonic counter**, ensuring no nonce is ever reused even under PRNG failure.
20. **H20** — The protocol supports **version negotiation**. Unsupported or deprecated versions are rejected.
21. **H21** — The system supports **coexistence** with legacy API key authentication during a migration period, with both mechanisms usable simultaneously on a per-endpoint basis.
22. **H22** — Enterprise-tier enrollment requires **identity verification** (per eIDAS requirements), while standard tier requires only proof of possession.
23. **H23** — All secret values are **zeroed from memory** (zeroize) immediately after use, on all platforms including WASM.

---

## Client Registration

### Feature: Client Enrollment

```gherkin
Feature: Client Enrollment
  As a client application developer
  I want to register my application with the authentication service
  So that I can later prove my identity using zero-knowledge proofs

  Background:
    Given the authentication service is operational
    And the public parameters (generators g and h) are published

  # --- Happy Path ---

  Scenario: Successful client enrollment with valid commitment and proof of possession
    Given Alice has generated a secret "s_alice_001" and a blinding factor "r_alice_001" on her device
    And Alice has computed her commitment from these values using the public parameters
    And Alice has generated a proof of possession demonstrating she knows the commitment opening
    And Alice has chosen the client identifier "alice-payment-service"
    When Alice submits her enrollment request with her identifier, commitment, and proof of possession
    Then Alice's enrollment is accepted
    And her commitment is stored in the registry
    And her client status is set to "active"
    And a "ClientEnrolled" event is published with client identifier "alice-payment-service"
    And the enrollment is recorded in the audit log

  # --- Business Rule Variations ---

  Scenario: Enrollment assigns unique internal identity regardless of chosen identifier
    Given Alice submits an enrollment with client identifier "alice-payment-service"
    When the enrollment is accepted
    Then an opaque internal identity is assigned to Alice's registration
    And this internal identity is never exposed in error messages

  Scenario: Public parameters are deterministic and independently verifiable
    Given the public parameters include generators g and h and the seed used to derive them
    When Alice verifies the public parameters by re-deriving g and h from the published seed
    Then the re-derived generators match the published generators exactly
    And Alice can confirm no party knows the discrete logarithm relationship between g and h

  # --- Edge Cases ---

  Scenario: Enrollment with commitment at the boundary of the valid group
    Given Alice has computed a commitment that is a valid group element but at the minimum representable point
    And Alice provides a valid proof of possession
    When Alice submits her enrollment request
    Then Alice's enrollment is accepted
    And her commitment is stored as-is

  Scenario: Enrollment rejected when commitment is the identity element
    Given Alice has computed a commitment that equals the identity element (neutral point)
    When Alice submits her enrollment request
    Then Alice's enrollment is refused
    And the reason indicates the commitment is invalid
    And the rejection is recorded in the audit log

  Scenario: Enterprise-tier enrollment requires identity verification
    Given Alice requests enrollment at the enterprise tier
    And Alice has not completed the identity verification process
    When Alice submits her enrollment request
    Then Alice's enrollment is refused
    And the reason indicates identity verification is required for the enterprise tier
    And Alice is directed to the identity verification process

  # --- Error Cases ---

  Scenario: Enrollment rejected for duplicate client identifier
    Given a client with identifier "alice-payment-service" is already registered
    When Alice submits an enrollment request with identifier "alice-payment-service"
    Then Alice's enrollment is refused
    And the reason indicates the identifier is already taken
    And the rejection is recorded in the audit log

  Scenario: Enrollment rejected for malformed commitment
    Given Alice submits an enrollment with a commitment that is not a valid group element
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates the commitment format is invalid
    And no data is stored in the registry

  Scenario: Enrollment rejected for non-canonical point encoding
    Given Alice submits an enrollment with a commitment encoded in a non-canonical byte representation
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates the encoding is invalid

  Scenario: Enrollment rejected for missing commitment
    Given Alice submits an enrollment request without a commitment
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates the commitment is required

  Scenario: Enrollment rejected without proof of possession
    Given Alice submits a valid commitment but without a proof of possession
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates proof of possession is required

  Scenario: Enrollment rejected when Eve submits a stolen commitment
    Given Eve has copied Alice's commitment from a public source
    And Eve generates a proof of possession attempt without knowing Alice's secret or blinding factor
    When Eve submits an enrollment with Alice's commitment under identifier "eve-fake-service"
    Then Eve's enrollment is refused because the proof of possession is invalid
    And the rejection is recorded in the audit log

  Scenario: Enrollment rejected when service is at capacity
    Given the registry has reached its maximum number of registered clients
    When Alice submits an enrollment request
    Then Alice's enrollment is refused
    And the reason indicates the service is temporarily at capacity
```

### Feature: Client Revocation

```gherkin
Feature: Client Revocation
  As a server administrator
  I want to revoke a registered client
  So that the client can no longer authenticate or access protected resources

  Background:
    Given the authentication service is operational
    And a client "alice-payment-service" is registered with status "active"

  # --- Happy Path ---

  Scenario: Successful immediate client revocation
    Given Alice has an active access token "token_abc"
    And Alice has a pending challenge "challenge_xyz"
    When Bob revokes the client "alice-payment-service"
    Then Alice's client status is changed to "revoked"
    And the active token "token_abc" is immediately invalidated
    And the pending challenge "challenge_xyz" is immediately invalidated
    And a "ClientRevoked" event is published
    And the revocation is recorded in the audit log with Bob's administrator identity

  # --- Error Cases ---

  Scenario: Revocation of an already revoked client is idempotent
    Given Alice's client status is already "revoked"
    When Bob revokes the client "alice-payment-service" again
    Then the operation completes without error
    And Alice's status remains "revoked"
    And the repeated revocation is recorded in the audit log

  Scenario: Revocation of an unknown client is indistinguishable from success
    When Bob attempts to revoke an unknown client "eve-fake-service"
    Then the response is identical to a successful revocation
    And no state change occurs
    And the attempt is recorded in the audit log
```

### Feature: Commitment Rotation

```gherkin
Feature: Commitment Rotation
  As a client application developer
  I want to rotate my commitment to a new secret
  So that I can maintain security hygiene without service interruption

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and an active commitment

  # --- Happy Path ---

  Scenario: Successful authenticated commitment rotation
    Given Alice proves knowledge of her current commitment opening
    And Alice has generated a new secret "s_alice_002" and blinding factor "r_alice_002"
    And Alice has computed a new commitment from these new values
    When Alice submits a rotation request with her proof and new commitment
    Then the old commitment is replaced by the new commitment
    And all active tokens issued under the old commitment are invalidated
    And a "CommitmentRotated" event is published
    And the rotation is recorded in the audit log

  # --- Edge Cases ---

  Scenario: Rotation with same commitment value is rejected
    Given Alice submits a rotation request where the new commitment equals the current one
    When the rotation request is processed
    Then the rotation is refused
    And the reason indicates the new commitment must differ from the current one

  Scenario: Concurrent rotation requests are serialized
    Given Alice sends two rotation requests simultaneously with different new commitments
    When both requests are processed
    Then exactly one rotation succeeds
    And the other is refused because the current commitment has changed

  # --- Error Cases ---

  Scenario: Rotation rejected without valid proof of current commitment
    Given Alice submits a rotation request without proving knowledge of her current commitment
    When the rotation request is processed
    Then the rotation is refused
    And the failure is recorded in the audit log
    And the failed attempt counts toward the lockout threshold

  Scenario: Rotation rejected for revoked client
    Given Alice's client status is "revoked"
    When Alice submits a rotation request
    Then the rotation is refused
    And the response is indistinguishable from an unknown client error

  Scenario: Rotation rejected for locked-out client
    Given Alice's client is currently locked out due to failed authentication attempts
    When Alice submits a rotation request
    Then the rotation is refused
    And the lockout duration is not reset
```

---

## Authentication Challenge

### Feature: Challenge Issuance

```gherkin
Feature: Challenge Issuance
  As a client application
  I want to request an authentication challenge from the server
  So that I can generate a zero-knowledge proof bound to a fresh nonce

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and status "active"

  # --- Happy Path ---

  Scenario: Successful challenge issuance with fresh unique nonce
    Given Alice presents her client identifier and valid credential
    When Alice requests an authentication challenge
    Then a fresh nonce is generated using a cryptographic random source combined with a monotonic counter
    And the nonce has never been issued before to any client
    And the challenge includes the nonce, a channel binding value, and an expiry timestamp
    And the expiry is set to 2 minutes from issuance
    And the challenge is recorded in the session store
    And any previously pending challenge for Alice is invalidated
    And a "ChallengeIssued" event is published

  # --- Edge Cases ---

  Scenario: New challenge request invalidates the previous pending challenge
    Given Alice already has a pending challenge "challenge_old" issued 30 seconds ago
    When Alice requests a new authentication challenge
    Then a new challenge "challenge_new" is issued
    And the previous challenge "challenge_old" is immediately invalidated
    And only "challenge_new" can be used to authenticate

  Scenario: Challenge issued at exact capacity limit
    Given the session store is at 99% capacity
    When Alice requests a challenge
    Then the challenge is issued normally
    And the system emits a capacity warning alert

  Scenario: Challenge request using legacy API key during migration period
    Given Alice is registered for both legacy API key and zero-knowledge authentication
    And the endpoint supports both authentication mechanisms during the migration period
    When Alice requests a challenge using her legacy API key as the first factor
    Then the challenge is issued with a flag indicating legacy first-factor was used
    And the audit log records that legacy authentication was used

  # --- Error Cases ---

  Scenario: Challenge refused for invalid credential
    Given Alice presents an incorrect credential
    When Alice requests an authentication challenge
    Then the challenge request is refused
    And the response is indistinguishable from an unknown client refusal
    And the failure is recorded in the audit log
    And the failed attempt counts toward the lockout threshold

  Scenario: Challenge refused for revoked client
    Given Alice's client status is "revoked"
    When Alice requests an authentication challenge
    Then the challenge request is refused
    And the response is indistinguishable from an unknown client refusal

  Scenario: Challenge refused for locked-out client
    Given Alice has failed 3 consecutive authentication attempts
    And Alice's lockout started 10 minutes ago
    When Alice requests a challenge
    Then the challenge request is refused
    And the response indicates the client is temporarily blocked
    And the response confirms the lockout exists but does not disclose the remaining duration

  Scenario: Challenge refused when verification service is unavailable
    Given the verification service is not reachable
    When Alice requests a challenge
    Then the challenge request is refused
    And no challenge is stored
    And the unavailability is recorded in the audit log

  Scenario: Challenge refused for unsupported protocol version
    Given Alice requests a challenge specifying protocol version "0.1-deprecated"
    And the server only supports version "1.0"
    When the challenge request is processed
    Then the request is refused
    And the response indicates the protocol version is not supported
    And the response includes the list of supported versions
```

### Feature: Challenge Expiry

```gherkin
Feature: Challenge Expiry
  As the authentication system
  I want challenges to expire after a strict time limit
  So that stale nonces cannot be used to forge proofs

  Background:
    Given the authentication service is operational

  # --- Happy Path ---

  Scenario: Challenge used within validity window succeeds
    Given Alice received a challenge 90 seconds ago with a 2-minute expiry
    When Alice submits a proof bound to this challenge
    Then the challenge is considered valid for verification purposes

  # --- Edge Cases ---

  Scenario: Challenge used at exact expiry boundary is rejected (strictly less than)
    Given Alice received a challenge exactly 120 seconds ago with a 2-minute expiry
    When Alice submits a proof bound to this challenge
    Then the challenge is considered expired because validity requires strictly less than 2 minutes elapsed
    And the proof is not verified
    And Alice must request a new challenge

  Scenario: Expired challenges are automatically purged from the session store
    Given a challenge was issued 5 minutes ago and has expired
    When the system performs periodic cleanup
    Then the expired challenge is removed from the session store
    And no trace remains except the audit log entry

  # --- Error Cases ---

  Scenario: Proof submitted with an expired challenge is rejected
    Given Alice received a challenge 3 minutes ago with a 2-minute expiry
    When Alice submits a proof bound to this expired challenge
    Then the verification is refused
    And the reason indicates the challenge has expired
    And the expired attempt is recorded in the audit log
    And the failed attempt does NOT count toward the lockout threshold

  Scenario: Proof submitted with an unknown challenge identifier is rejected
    Given Alice submits a proof referencing a challenge identifier "nonexistent_challenge"
    When the verification is attempted
    Then the verification is refused
    And the response is indistinguishable from an expired challenge refusal
```

### Feature: Nonce Uniqueness Guarantee

```gherkin
Feature: Nonce Uniqueness Guarantee
  As the authentication system
  I want every nonce to be globally unique
  So that a nonce reuse can never lead to secret extraction

  Background:
    Given the authentication service is operational

  # --- Happy Path ---

  Scenario: Each nonce is unique across all clients and all time
    Given the server issues 1000000 challenges to various clients over 24 hours
    When the nonces are collected
    Then every nonce is unique
    And no two nonces share the same value

  # --- Edge Cases ---

  Scenario: Nonce uniqueness holds even if the random source produces a collision
    Given the cryptographic random source produces a value that was previously generated
    When the server constructs the nonce by combining the random value with the monotonic counter
    Then the resulting nonce is still unique because the counter component differs
    And the challenge is issued normally

  # --- Error Cases ---

  Scenario: Challenge issuance fails if the monotonic counter overflows
    Given the monotonic counter has reached its maximum value
    When Alice requests a challenge
    Then the challenge request is refused
    And the reason indicates a service error
    And a critical alert is generated for counter exhaustion
```

---

## Zero-Knowledge Verification

### Feature: Proof Generation (Client-Side)

```gherkin
Feature: Proof Generation
  As a client application
  I want to generate a zero-knowledge proof of my commitment opening
  So that I can authenticate without revealing my secret

  Background:
    Given Alice has her secret "s_alice_001" and blinding factor "r_alice_001"
    And Alice has received a valid challenge with nonce "n_challenge_42" and channel binding value "tls_binding_xyz"

  # --- Happy Path ---

  Scenario: Successful proof generation with domain-separated transcript
    When Alice generates a proof for her commitment opening
    Then the proof includes the prover's announcement (first message)
    And the proof includes the challenge value derived from the full transcript
    And the transcript begins with the domain separation tag "2FApi-v1.0-Sigma"
    And the transcript includes the public parameters, Alice's stored commitment, the nonce "n_challenge_42", and the channel binding "tls_binding_xyz"
    And the proof includes the response values
    And the proof is generated using a fresh random nonce from a cryptographic source
    And Alice's secret and blinding factor are zeroed from memory immediately after proof generation

  # --- Edge Cases ---

  Scenario: Proof generation with secret equal to zero
    Given Alice's secret is the scalar value zero
    And Alice has a valid blinding factor
    When Alice generates a proof
    Then the proof is generated successfully
    And the proof is verifiable against Alice's commitment

  Scenario: Proof generation with blinding factor equal to zero
    Given Alice has a valid secret
    And Alice's blinding factor is the scalar value zero
    When Alice generates a proof
    Then the proof is generated successfully
    And the proof is verifiable against Alice's commitment

  Scenario: Proof generation with response scalar equal to zero
    Given Alice's random nonce and secret values are such that the response scalar equals zero
    When Alice generates a proof
    Then the proof is generated successfully
    And the zero response scalar is a valid mathematical result
    And the proof is verifiable against Alice's commitment

  Scenario: Proof generated in WASM is identical to proof generated natively for same inputs
    Given Alice uses a deterministic random source with seed "test_seed_001"
    And Alice generates a proof using the native Rust implementation
    And Alice generates a proof using the WASM implementation with the same seed
    When the two proofs are compared
    Then they are byte-for-byte identical
    And both verify successfully against Alice's commitment

  Scenario: Secret and blinding factor are zeroed from memory after proof generation
    Given Alice generates a proof successfully
    When the proof generation function returns
    Then the memory locations that held the secret "s_alice_001" are overwritten with zeros
    And the memory locations that held the blinding factor "r_alice_001" are overwritten with zeros
    And this holds on all platforms including WASM

  # --- Error Cases ---

  Scenario: Proof generation fails when random source is unavailable
    Given the cryptographic random number generator is unavailable on Alice's device
    When Alice attempts to generate a proof
    Then the proof generation fails
    And no partial proof data is emitted
    And the error indicates that secure randomness is required

  Scenario: Proof generation fails with expired challenge
    Given Alice's challenge has a local timestamp indicating expiry has passed
    When Alice attempts to generate a proof
    Then the proof generation is refused locally
    And Alice is prompted to request a new challenge
```

### Feature: Proof Verification (Server-Side)

```gherkin
Feature: Proof Verification
  As the authentication server
  I want to verify zero-knowledge proofs submitted by clients
  So that only clients who know their secret can access protected resources

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and an active commitment
    And Alice has a valid pending challenge with nonce "n_challenge_42"

  # --- Happy Path ---

  Scenario: Successful proof verification grants authentication
    Given Alice submits a valid proof bound to nonce "n_challenge_42" and the current channel binding
    And the proof transcript includes the correct domain separation tag "2FApi-v1.0-Sigma"
    When the server verifies the proof against Alice's stored commitment
    Then the verification succeeds
    And the used challenge is consumed and cannot be reused
    And a "ProofVerified" event is published with client identifier "alice-payment-service"
    And the success is recorded in the audit log
    And the failed attempt counter for Alice is reset to zero

  # --- Business Rule Variations ---

  Scenario Outline: Verification result is independent of client identifier length
    Given a client with identifier "<client_id>" is registered with a valid commitment
    And the client has a valid pending challenge
    And the client submits a valid proof
    When the server verifies the proof
    Then the verification succeeds

    Examples:
      | client_id                                      |
      | a                                              |
      | alice-payment-service                          |
      | very-long-client-identifier-that-is-128-chars-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |

  # --- Edge Cases ---

  Scenario: Verification with correct proof but wrong channel binding is rejected
    Given Alice submits a proof that is mathematically valid
    But the proof's channel binding value does not match the current connection
    When the server verifies the proof
    Then the verification is refused
    And the reason is indistinguishable from an invalid proof
    And the failure is recorded in the audit log
    And the failed attempt counter is incremented

  Scenario: Verification timing is constant regardless of failure reason
    Given Eve submits a proof with an unknown client identifier
    And Alice submits a proof with an incorrect response value
    And Charlie submits a proof with an expired challenge
    When all three verifications are processed
    Then the time taken for all three refusal responses is indistinguishable within measurement precision

  Scenario: Second use of a consumed challenge is rejected
    Given Alice's challenge "n_challenge_42" was already used for a successful verification
    When Alice submits another proof bound to the same challenge
    Then the verification is refused
    And the reason indicates the challenge has already been consumed

  Scenario: Proof for a rotated commitment is rejected
    Given Alice's commitment was rotated after the challenge was issued
    When Alice submits a proof generated against the old commitment
    Then the verification is refused
    And the failure is recorded in the audit log

  Scenario: Proof with wrong domain separation tag is rejected
    Given Alice submits a proof where the transcript uses domain tag "OtherProtocol-v1.0" instead of "2FApi-v1.0-Sigma"
    When the server verifies the proof
    Then the verification is refused
    And the failure is recorded in the audit log

  Scenario: Client revoked between challenge issuance and proof submission
    Given Alice received a valid challenge 30 seconds ago
    And Bob revokes Alice's client 10 seconds after the challenge was issued
    When Alice submits a valid proof 20 seconds after revocation
    Then the verification is refused because Alice's client is revoked
    And the challenge has been invalidated by the revocation
    And the attempt is recorded in the audit log

  Scenario: Batch verification of multiple simultaneous proofs
    Given 100 different clients each submit a valid proof simultaneously
    When the server processes all 100 proofs
    Then all 100 verifications succeed
    And each individual invalid proof within a batch is rejected independently
    And the total verification time is less than 100 times the single-proof verification time

  Scenario: Server maintains verification under 5 milliseconds at 10000 concurrent requests
    Given the server is under load with 10000 concurrent verification requests
    When each proof is verified
    Then the p99 verification latency remains under 5 milliseconds
    And no verification is dropped or timed out

  # --- Error Cases ---

  Scenario: Invalid proof with incorrect response values is rejected
    Given Alice submits a proof where the response values do not satisfy the verification equation
    When the server verifies the proof
    Then the verification is refused
    And the response is indistinguishable from an unknown client refusal
    And the failed attempt counter is incremented
    And the failure is recorded in the audit log

  Scenario: Proof with a single bit flipped is rejected (malleability resistance)
    Given Eve captures a valid proof from Alice
    And Eve flips one bit in the proof's response value
    When Eve submits the modified proof
    Then the verification is refused
    And the response is indistinguishable from any other proof failure
    And the attempt is recorded in the audit log

  Scenario: Malformed proof with invalid encoding is rejected
    Given Alice submits a proof containing bytes that are not valid group or scalar elements
    When the server attempts to verify the proof
    Then the verification is refused before any cryptographic computation
    And the malformed input is recorded in the audit log

  Scenario: Proof with non-canonical scalar encoding is rejected
    Given Alice submits a proof where a scalar value is not reduced modulo the group order
    When the server processes the proof
    Then the verification is refused
    And the reason indicates invalid encoding

  Scenario: Proof with non-canonical point encoding is rejected
    Given Alice submits a proof where a group element has a non-canonical compressed representation
    When the server processes the proof
    Then the verification is refused
    And the reason indicates invalid encoding

  Scenario: Proof with the identity point as announcement is rejected
    Given Alice submits a proof where the prover's announcement is the identity element
    When the server processes the proof
    Then the verification is refused
    And the failure is recorded in the audit log
```

### Feature: Replay Protection

```gherkin
Feature: Replay Protection
  As the authentication system
  I want to prevent the reuse of valid proofs
  So that a captured proof cannot be used to impersonate a client

  Background:
    Given the authentication service is operational
    And Alice is registered and has completed a successful authentication

  # --- Happy Path ---

  Scenario: Each authentication requires a fresh challenge-proof pair
    Given Alice wants to authenticate a second time
    When Alice requests a new challenge
    And Alice generates a fresh proof bound to the new nonce
    And Alice submits the fresh proof
    Then the verification succeeds
    And this is treated as an independent authentication event

  # --- Error Cases ---

  Scenario: Replaying a previously valid proof is rejected
    Given Eve has captured Alice's valid proof from a previous authentication
    When Eve submits Alice's captured proof
    Then the verification is refused because the challenge has been consumed
    And the replay attempt is recorded in the audit log as suspicious activity

  Scenario: Replaying a proof on a different connection is rejected
    Given Eve has captured Alice's valid proof including the channel binding
    And Eve opens a new connection to the server
    When Eve submits Alice's captured proof on the new connection
    Then the verification is refused because the channel binding does not match
    And the attempt is recorded in the audit log as suspicious activity

  Scenario: Proof generated with a guessed nonce is rejected
    Given Eve generates a proof using a nonce she fabricated ("fake_nonce_99")
    When Eve submits this proof
    Then the verification is refused because no matching challenge exists
    And the response is indistinguishable from an expired challenge refusal

  Scenario: Reflection attack is rejected — server message reflected back to server
    Given Eve captures the challenge message sent by the server to Alice
    And Eve sends this challenge message back to the server as if it were a proof
    When the server processes the reflected message
    Then the message is rejected because it does not conform to the proof format
    And the attempt is recorded in the audit log as suspicious activity
```

### Feature: Denial-of-Service Resistance

```gherkin
Feature: Denial-of-Service Resistance
  As the authentication system
  I want to resist denial-of-service attacks targeting the verification process
  So that legitimate clients are not impacted by attackers flooding with expensive operations

  Background:
    Given the authentication service is operational

  # --- Happy Path ---

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
```

---

## API Access Control

### Feature: Token Issuance

```gherkin
Feature: Token Issuance
  As the authentication server
  I want to issue short-lived, audience-restricted access tokens after successful two-factor authentication
  So that authenticated clients can access only their intended protected resources within a strict time window

  Background:
    Given the authentication service is operational
    And Alice has successfully completed both authentication factors

  # --- Happy Path ---

  Scenario: Access token issued after successful two-factor authentication
    When the server issues an access token for Alice targeting service "payment-api"
    Then the token has a maximum lifetime of 15 minutes
    And the token is bound to Alice's client identifier
    And the token is bound to the current connection's channel binding
    And the token includes an audience claim restricted to "payment-api"
    And a "TokenIssued" event is published
    And the token issuance is recorded in the audit log

  Scenario: Token for step-up authentication on sensitive resource
    Given Alice holds a valid access token for "payment-api"
    And Alice requests access to a sensitive operation "initiate-transfer"
    When the server requires step-up authentication for this operation
    Then Alice must complete the full two-factor authentication again
    And upon success a new token is issued with an elevated scope for "initiate-transfer"
    And the elevated token has a reduced lifetime of 5 minutes

  # --- Edge Cases ---

  Scenario: Token is not renewable — re-authentication is required
    Given Alice's access token was issued 14 minutes ago
    When Alice attempts to extend or renew her token
    Then the renewal is refused
    And Alice must complete the full two-factor authentication again

  Scenario: Token issued immediately before client revocation
    Given Alice receives a valid access token
    And Bob revokes Alice 1 second later
    When Alice attempts to use the token
    Then the token is rejected because Alice's client is revoked
    And the revocation took effect immediately

  Scenario: Token for wrong audience is rejected (confused deputy protection)
    Given Alice holds a valid access token with audience "payment-api"
    When Alice presents this token to service "user-management-api"
    Then access is denied
    And the reason indicates the token audience does not match the service
    And the mismatch is recorded in the audit log

  # --- Error Cases ---

  Scenario: Token rejected after expiry
    Given Alice received an access token 16 minutes ago
    When Alice presents this token to access a protected resource
    Then access is denied
    And the reason indicates the token has expired
    And the expired token attempt is recorded in the audit log

  Scenario: Token rejected when presented on a different connection
    Given Alice received an access token bound to connection "conn_A"
    When Alice presents this token on connection "conn_B"
    Then access is denied
    And the reason is indistinguishable from an expired token refusal
    And the mismatch is recorded in the audit log as suspicious activity

  Scenario: Forged token with invalid signature is rejected
    Given Eve presents a fabricated access token
    When the token is validated
    Then access is denied
    And the response time is indistinguishable from a valid-but-expired token check
```

### Feature: Resource Access

```gherkin
Feature: Resource Access
  As a client application
  I want to access protected resources using my access token
  So that I can perform authorized operations

  Background:
    Given the authentication service is operational
    And Alice holds a valid, non-expired access token with the correct audience

  # --- Happy Path ---

  Scenario: Authenticated client accesses a protected resource
    Given Alice's token is valid, not expired, and audience-matched
    And Alice's client status is "active"
    When Alice requests access to a protected resource
    Then access is granted
    And the resource is served
    And the access is recorded in the audit log

  # --- Edge Cases ---

  Scenario: Access attempt with token 1 second before expiry succeeds
    Given Alice's token expires in 1 second
    When Alice requests access to a protected resource
    Then access is granted

  Scenario: Multiple sequential requests with the same valid token succeed
    Given Alice's token is valid for another 10 minutes
    When Alice makes 100 consecutive requests to protected resources
    Then all 100 requests are granted

  # --- Error Cases ---

  Scenario: Unauthenticated request to a protected resource is rejected
    Given Eve does not present any access token
    When Eve requests access to a protected resource
    Then access is denied
    And the response includes instructions to authenticate

  Scenario: Request with malformed token is rejected
    Given Eve presents a token that is not in the expected format
    When the token is validated
    Then access is denied
    And the malformed token attempt is recorded in the audit log

  Scenario: Request after client revocation is rejected even with valid token
    Given Alice has a valid access token
    And Bob revokes Alice's client
    When Alice requests access to a protected resource
    Then access is denied
    And the reason is indistinguishable from an expired token refusal
```

---

## Security Monitoring

### Feature: Failed Attempt Tracking

```gherkin
Feature: Failed Attempt Tracking
  As the authentication system
  I want to track consecutive failed authentication attempts per client
  So that I can lock out clients exhibiting brute-force behavior

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and status "active"

  # --- Happy Path ---

  Scenario: Failed attempt counter increments on each failure
    Given Alice has 0 consecutive failed attempts
    When Alice submits an invalid proof
    Then the failed attempt counter increases to 1
    And Alice can still request new challenges

  Scenario: Successful authentication resets the failed attempt counter
    Given Alice has 2 consecutive failed attempts
    When Alice submits a valid proof
    Then the verification succeeds
    And the failed attempt counter is reset to 0

  # --- Edge Cases ---

  Scenario: Failed attempt on expired challenge does not count toward lockout
    Given Alice submits a proof against an expired challenge
    When the verification is refused due to expiry
    Then the failed attempt counter is not incremented
    And Alice is not penalized

  Scenario Outline: Lockout triggers at exactly the threshold
    Given Alice has <current_failures> consecutive failed attempts
    When Alice submits an invalid proof
    Then the failed attempt counter becomes <new_count>
    And Alice's lockout status is "<lockout_status>"

    Examples:
      | current_failures | new_count | lockout_status |
      | 0                | 1         | not locked     |
      | 1                | 2         | not locked     |
      | 2                | 3         | locked         |

  # --- Error Cases ---

  Scenario: Locked-out client is notified of lockout status
    Given Alice has reached 3 consecutive failed attempts
    And Alice was locked out 30 minutes ago
    When Alice requests a new challenge
    Then the request is refused
    And the response indicates the client is temporarily blocked
    And the response confirms the lockout exists per NIST AAL2 requirements
    And the remaining lockout duration is not disclosed to limit attacker information

  Scenario: Lockout expires after 60 minutes allowing retry
    Given Alice was locked out 61 minutes ago
    When Alice requests a new challenge with valid credential
    Then the challenge is issued
    And the failed attempt counter remains at 3 (not reset until successful auth)
```

### Feature: Audit Trail

```gherkin
Feature: Audit Trail
  As a server administrator
  I want every security-relevant event to be recorded in an immutable audit log
  So that I can investigate incidents and meet compliance requirements

  Background:
    Given the audit logging system is operational

  # --- Happy Path ---

  Scenario: Successful enrollment is audited
    When Alice completes a successful enrollment
    Then the audit log contains an entry with event type "enrollment_success"
    And the entry includes the client identifier, timestamp, and source address
    And the entry does NOT include any secret or blinding factor values

  Scenario: Failed authentication is audited with failure reason
    When Alice submits an invalid proof
    Then the audit log contains an entry with event type "authentication_failure"
    And the entry includes the client identifier, timestamp, failure reason, and attempt count
    And the entry does NOT include the proof data or any secret values

  Scenario: Audit log entries are retained for the required duration
    Given the system is configured for standard retention (12 months) and regulated retention (5 years)
    When an audit entry is recorded on 2026-01-15
    Then the entry is available for retrieval until at least 2027-01-15 under standard retention
    And the entry is available for retrieval until at least 2031-01-15 under regulated retention
    And the retention policy is enforced automatically

  # --- Edge Cases ---

  Scenario: Audit log entries are immutable
    Given an audit entry was recorded 1 hour ago
    When an administrator attempts to modify the entry
    Then the modification is refused
    And an alert is generated for audit log tampering attempt

  Scenario: High-volume events do not cause audit log data loss
    Given 10000 authentication attempts occur within 1 second
    When the audit system processes the events
    Then all 10000 events are recorded with correct timestamps
    And no events are dropped or merged

  # --- Error Cases ---

  Scenario: Audit log unavailability causes authentication to fail safe
    Given the audit logging system is unavailable
    When Alice attempts to authenticate
    Then the authentication is refused
    And the reason indicates a temporary service unavailability
    And no authentication proceeds without audit logging

  Scenario: Audit entry for unknown event type is recorded as anomaly
    Given the system encounters an event that does not match any known event type
    When the event is sent to the audit system
    Then the event is recorded with type "unknown_event"
    And an alert is generated for investigation
```

### Feature: Anomaly Detection

```gherkin
Feature: Anomaly Detection
  As a server administrator
  I want to detect suspicious authentication patterns
  So that I can respond to potential attacks before damage occurs

  Background:
    Given the authentication service and monitoring are operational

  # --- Happy Path ---

  Scenario: Distributed brute-force attack detected across multiple clients
    Given 50 different clients each fail authentication once within 1 minute
    When the anomaly detection system analyzes the pattern
    Then a "distributed_brute_force" alert is generated
    And the alert includes the time window, number of clients, and source addresses

  Scenario: Unusual authentication volume from single client triggers alert
    Given Alice typically authenticates 10 times per hour
    When Alice authenticates 200 times within 1 hour
    Then a "volume_anomaly" alert is generated for client "alice-payment-service"
    And Alice's authentications continue to be processed (alert only, no block)

  # --- Edge Cases ---

  Scenario: Rapid successful authentications from legitimate automation are not flagged
    Given Alice has an established baseline of 100 authentications per hour
    When Alice authenticates 120 times in 1 hour
    Then no anomaly alert is generated
    And the baseline is updated to reflect the new pattern

  Scenario: Lockout of multiple clients simultaneously triggers escalation
    Given 10 different clients are locked out within a 5-minute window
    When the anomaly detection system analyzes the pattern
    Then a "mass_lockout" critical alert is generated
    And the alert is escalated to the on-call administrator

  # --- Error Cases ---

  Scenario: Anomaly detection failure does not block authentication
    Given the anomaly detection system is experiencing an internal error
    When Alice attempts to authenticate
    Then the authentication proceeds normally
    And the anomaly detection failure is recorded in the system health log
    And an alert is generated for the monitoring system failure

  Scenario: Proof submission from revoked client triggers immediate alert
    Given Alice's client was revoked 1 hour ago
    When someone submits a proof using Alice's client identifier
    Then the authentication is refused
    And a "revoked_client_activity" alert is generated immediately
    And the alert includes the source address and timestamp
```
