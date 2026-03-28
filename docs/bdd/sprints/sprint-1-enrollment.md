# Sprint 1 — Client Enrollment

> **Goal**: A client can register with the service by providing a Pedersen commitment and proof of possession.
> **Bounded Context**: Client Registration
> **Scenarios**: 19 | Happy: 3 | Edge: 5 | Error: 11
> **Prerequisites**: None (foundational sprint)
> **Key deliverables**: Enrollment use case, commitment registry, proof of possession verification, public parameter setup

---

## Feature: Public Parameter Verification (Utility)

```gherkin
Feature: Public Parameter Verification (Utility)
  As a client application developer
  I want to independently verify the public parameters used by the authentication service
  So that I can trust no party has a trapdoor over the generators

  Background:
    Given this is a one-time system-wide setup, not a per-enrollment operation

  Scenario: Public parameters are deterministic and independently verifiable
    Given the public parameters include generators g and h
    And each generator is derived via hash-to-curve with a distinct domain separation tag
    When Alice re-derives g and h from the published seed and domain separation tags
    Then the re-derived generators match the published generators exactly
    And Alice can confirm nothing-up-my-sleeve derivation, making dlog knowledge computationally infeasible
```

---

## Feature: Client Enrollment

```gherkin
Feature: Client Enrollment
  As a client application developer
  I want to register my application with the authentication service
  So that I can later prove my identity using zero-knowledge proofs

  Background:
    Given the authentication service is operational
    And the public parameters (generators g and h) are published
    And the validation pipeline processes in order:
      | Step | Check                                          |
      | 1    | Canonical encoding (unique Ristretto255 32-byte compressed) |
      | 2    | Valid group element                             |
      | 3    | Not the identity element                        |
      | 4    | Proof of possession                             |
    And the Sigma verification equation is: g^z_s * h^z_r == A + C * c
    And the ProofOfPossessionVerifier MUST verify in constant time

  # --- Happy Path ---

  Scenario: Successful client enrollment with valid commitment and proof of possession
    Given Alice has generated a secret s and a blinding factor r as random scalars in the valid scalar range on her device
    And Alice has computed her commitment C = g^s * h^r using the public parameters
    And Alice has generated a proof of representation demonstrating knowledge of (s, r) such that C = g^s * h^r
    And the Fiat-Shamir transcript binds g, h, C, A, client_id, and a domain separation tag
    And Alice has chosen the client identifier "alice-payment-service"
    When Alice submits her enrollment request with her identifier, commitment, and proof of possession
    Then Alice's enrollment is accepted
    And her commitment is stored in the registry
    And her client status is set to "active"
    And a "ClientEnrolled" event is published with client identifier "alice-payment-service"
    And Alice receives an enrollment receipt with a reference identifier
    And the enrollment is recorded in the audit log

  Scenario: Enrollment assigns unique internal identity regardless of chosen identifier
    Given Alice submits an enrollment with client identifier "alice-payment-service"
    When the enrollment is accepted
    Then an opaque internal identity is assigned to Alice's registration
    And this internal identity is generated via CSPRNG with a minimum of 128 bits
    And this internal identity is not derived from any input to the enrollment request
    And this internal identity is never exposed in error messages, logs, HTTP headers, or external event payloads

  Scenario: Idempotent retry with same identifier and commitment
    Given Alice has already been enrolled with identifier "alice-payment-service" and commitment C
    When Alice submits the same enrollment request with the same identifier and the same commitment C
    Then Alice receives an idempotent success response identical to the original enrollment receipt

  # --- Edge Cases ---

  Scenario: Enrollment with commitment at the smallest valid compressed encoding
    Given Alice has computed a commitment that is the smallest valid compressed Ristretto255 encoding
    And Alice provides a valid proof of possession
    When Alice submits her enrollment request
    Then Alice's enrollment is accepted
    And the stored commitment matches the exact bytes submitted

  Scenario: Enrollment rejected when commitment is the identity element
    Given Alice has computed a commitment that equals the identity element
    And the identity element is the Ristretto255 point encoding to 32 zero bytes
    When Alice submits her enrollment request
    Then Alice's enrollment is refused
    And the reason indicates the commitment is invalid
    And the rejection is recorded in the audit log

  Scenario: Concurrent duplicate enrollment results in exactly one acceptance
    Given Alice and Bob submit enrollment requests with the same identifier at the same time
    When both requests are processed concurrently
    Then exactly one enrollment is accepted
    And the other enrollment is refused
    And the system remains in a consistent state

  Scenario: Malleable commitment variant of an existing commitment is rejected
    Given a commitment C is already registered
    And Eve submits a commitment C' that is algebraically related to C
    And Eve provides a valid proof of possession for C'
    When Eve's enrollment request is processed
    Then Eve's enrollment is refused
    And the reason indicates the commitment is invalid

  Scenario: Request with unexpected or extra fields
    Given Alice submits an enrollment request containing additional fields beyond the expected schema
    When the enrollment request is processed
    Then the unexpected fields are ignored
    And the enrollment proceeds based on the recognized fields only

  # --- Error Cases ---

  Scenario: Enrollment rejected for duplicate client identifier
    Given a client with identifier "alice-payment-service" is already registered
    When Alice submits an enrollment request with identifier "alice-payment-service" but a different commitment
    Then Alice's enrollment is refused
    And the error response is indistinguishable from other enrollment failures to prevent identifier enumeration
    And the rejection is recorded in the audit log

  Scenario: Enrollment rejected for malformed commitment
    Given Alice submits an enrollment with a commitment that is not a valid group element
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates the commitment format is invalid
    And no data is stored in the registry

  Scenario: Enrollment rejected for non-canonical point encoding
    Given Alice submits an enrollment with a commitment that is not in the unique Ristretto255 32-byte compressed encoding
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
    And the audit log does NOT reveal the original owner of the commitment

  Scenario: Replay of a complete valid enrollment request is rejected
    Given Alice has already successfully enrolled
    And Eve captures and replays Alice's complete enrollment request verbatim
    When the replayed request is processed
    Then the replay is rejected
    And no duplicate registration is created

  Scenario: All-zero bytes submitted as proof of possession
    Given Alice submits a valid commitment
    And Alice submits a proof of possession consisting entirely of zero bytes
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates the proof of possession is invalid

  Scenario: Degenerate scalar values in proof of possession
    Given Alice submits a valid commitment
    And Alice submits a proof of possession where z_s = 0 or z_r = 0 or z_s and z_r are at the maximum scalar value
    When the enrollment request is processed
    Then Alice's enrollment is refused
    And the reason indicates the proof of possession is invalid

  Scenario: Rate limiting on enrollment attempts
    Given an IP address or client has exceeded the enrollment rate limit threshold
    When another enrollment request is submitted from that source
    Then the enrollment request is refused
    And the reason indicates rate limiting
    And the rejection is recorded in the audit log
```

---

## TDD Implementation Order

1. **RED**: One-time public parameters setup (hash-to-curve, deterministic, domain separation tags for g and h)
2. **RED**: Commitment validation pipeline — step 1: canonical Ristretto255 32-byte encoding check
3. **RED**: Commitment validation pipeline — step 2: valid group element check
4. **RED**: Commitment validation pipeline — step 3: not the identity element (32 zero bytes)
5. **RED**: Proof of possession verification (Sigma protocol: g^z_s * h^z_r == A + C * c, constant-time)
6. **RED**: Fiat-Shamir transcript binding (g, h, C, A, client_id, domain separation tag)
7. **RED**: Enrollment with valid commitment + proof → stored in registry, enrollment receipt with reference identifier
8. **RED**: Internal identity generation (CSPRNG, 128-bit minimum, no derivation from inputs, never leaked)
9. **RED**: Duplicate identifier rejection (error indistinguishable from other failures)
10. **RED**: Malleable commitment variant rejection (algebraically related C')
11. **RED**: Malformed / missing / non-canonical input rejection
12. **RED**: All-zero bytes proof of possession rejection
13. **RED**: Degenerate scalar values in proof (z_s=0, z_r=0, max value) rejection
14. **RED**: Stolen commitment rejection (invalid proof of possession, audit log hides original owner)
15. **RED**: Replay of valid enrollment request → rejected
16. **RED**: Idempotent retry (same identifier + same commitment → idempotent response)
17. **RED**: Concurrent duplicate enrollment → exactly one accepted
18. **RED**: Rate limiting on enrollment attempts
19. **RED**: Request with unexpected/extra fields handling
20. **RED**: Stored commitment matches exact bytes submitted
21. **RED**: Audit logging for all enrollment events
22. **RED**: ClientEnrolled domain event publication
