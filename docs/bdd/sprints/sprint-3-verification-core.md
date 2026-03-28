# Sprint 3 — Zero-Knowledge Verification (Core)

> **Goal**: Client can generate a zkProof and the server can verify it. Core protocol flow complete.
> **Bounded Context**: Zero-Knowledge Verification
> **Scenarios**: 25 | Happy: 4 | Edge: 9 | Error: 12
> **Prerequisites**: Sprint 1 (Registration), Sprint 2 (Challenges)
> **Key deliverables**: Proof generation (client), proof verification (server), replay protection, domain separation

---

## Feature: Proof Generation (Client-Side)

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

## Feature: Proof Verification (Server-Side)

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

  # --- Error Cases ---

  Scenario: Invalid proof with incorrect response values is rejected
    Given Alice submits a proof where the response values do not satisfy the verification equation
    When the server verifies the proof
    Then the verification is refused
    And the response is indistinguishable from an unknown client refusal
    And the failed attempt counter is incremented
    And the failure is recorded in the audit log

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

## Feature: Replay Protection

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

---

## TDD Implementation Order

1. **RED**: Domain separation tag construction ("2FApi-v1.0-Sigma")
2. **RED**: Fiat-Shamir transcript (tag + params + commitment + nonce + channel binding)
3. **RED**: Proof generation (announcement, challenge derivation, response)
4. **RED**: Memory zeroization after proof generation
5. **RED**: Proof verification equation (g^z_s · h^z_r == A + C^c)
6. **RED**: Valid proof → success + challenge consumed + counter reset
7. **RED**: Invalid response → indistinguishable refusal
8. **RED**: Wrong channel binding → refusal
9. **RED**: Wrong domain tag → refusal
10. **RED**: Non-canonical encoding (scalar + point) → refusal
11. **RED**: Identity point as announcement → refusal
12. **RED**: Consumed challenge reuse → refusal
13. **RED**: Replay protection (consumed nonce, wrong connection, fabricated nonce)
14. **RED**: Reflection attack → format rejection
15. **RED**: Constant-time verification (timing tests)
16. **RED**: Edge cases: zero secret, zero blinding, zero response scalar
17. **RED**: Revocation between challenge and proof → refusal
18. **RED**: Audit logging for all verification events
