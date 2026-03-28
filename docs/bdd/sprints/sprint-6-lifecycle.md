# Sprint 6 — Client Lifecycle (Rotation & Revocation)

> **Goal**: Registered clients can rotate their commitment and administrators can revoke clients instantly.
> **Bounded Context**: Client Registration (advanced features)
> **Scenarios**: 22 | Happy: 3 | Edge: 8 | Error: 11
> **Prerequisites**: Sprint 3 (Verification — rotation requires proof of current commitment)
> **Key deliverables**: Authenticated commitment rotation, immediate revocation, lifecycle events, cross-context event propagation

---

## Expert Review Summary

> **Cryptographer**: Enforced that rotation proof MUST use the same Fiat-Shamir transcript structure as Sprint 3 with dedicated domain separation tag "2FApi-v1.0-Rotation". Added rejection of identity-point and non-canonical commitments during rotation. Ensured new commitment requires proof of possession (same as enrollment).
>
> **Protocol Designer**: Added TOCTOU scenarios for rotation-during-verification and revocation-during-rotation. Added event propagation scenario (CommitmentRotated consumed by Authentication Challenge context). Added partial-state scenario for event publisher failure. Ensured concurrent rotation uses optimistic locking with version check.
>
> **Security Researcher**: Added rate limiting on rotation requests to prevent commitment-grinding attacks. Ensured revocation response timing is constant to prevent enumeration. Added scenario for admin identity requirement on revocation (audit trail). Verified that rotation proof failure counts toward lockout threshold.
>
> **IAM Expert**: Ensured revocation is permanent (no un-revoke; requires new enrollment). Added explicit admin identity binding for revocation audit trail. Clarified that revoked clients MUST re-enroll with a new identifier to regain access.

---

## Feature: Client Revocation

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
    When administrator Bob, authenticated with admin identity "bob-admin-id", revokes the client "alice-payment-service"
    Then Alice's client status is changed to "revoked"
    And the active token "token_abc" is immediately invalidated
    And the pending challenge "challenge_xyz" is immediately invalidated
    And a "ClientRevoked" event is published
    And the revocation is recorded in the audit log with Bob's administrator identity "bob-admin-id"
    And the revocation timestamp is recorded for compliance purposes

  # --- Edge Cases ---

  Scenario: Revocation of an already revoked client is idempotent
    Given Alice's client status is already "revoked"
    When administrator Bob revokes the client "alice-payment-service" again
    Then the operation completes without error
    And Alice's status remains "revoked"
    And the repeated revocation is recorded in the audit log
    And the response timing is indistinguishable from a first-time revocation

  Scenario: Revocation of an unknown client is indistinguishable from success
    When administrator Bob attempts to revoke an unknown client "eve-fake-service"
    Then the response is identical to a successful revocation
    And no state change occurs
    And the attempt is recorded in the audit log
    And the response timing is indistinguishable from a real revocation

  Scenario: Revocation is permanent — no un-revoke path exists
    Given Alice's client status is "revoked"
    When an administrator attempts to reactivate client "alice-payment-service"
    Then the reactivation is refused
    And the reason indicates that revocation is permanent
    And the administrator is informed that a new enrollment with a new identifier is required

  Scenario: Revocation during an ongoing proof verification (TOCTOU)
    Given Alice has submitted a valid proof that is currently being verified
    And administrator Bob revokes client "alice-payment-service" while the verification is in progress
    When the verification completes
    Then the verification is refused because Alice's client status is "revoked"
    And the revocation takes precedence over any in-flight verification
    And the attempt is recorded in the audit log

  # --- Error Cases ---

  Scenario: Revocation rejected without authenticated administrator identity
    When an unauthenticated caller attempts to revoke client "alice-payment-service"
    Then the revocation is refused
    And the reason indicates that administrator authentication is required
    And the attempt is recorded in the audit log as an unauthorized revocation attempt

  # (Additional error coverage: Sprint 3 scenario "Client revoked between challenge issuance and proof submission")
```

## Feature: Commitment Rotation

```gherkin
Feature: Commitment Rotation
  As a client application developer
  I want to rotate my commitment to a new secret
  So that I can maintain security hygiene without service interruption

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and an active commitment
    And the rotation Fiat-Shamir transcript uses domain separation tag "2FApi-v1.0-Rotation"
    And the rotation transcript includes the public parameters, the current commitment, the new commitment, and a server-issued rotation nonce

  # --- Happy Path ---

  Scenario: Successful authenticated commitment rotation
    Given Alice proves knowledge of her current commitment opening using the rotation Sigma protocol
    And the rotation proof uses the Fiat-Shamir transcript with domain separation tag "2FApi-v1.0-Rotation"
    And Alice has generated a new secret "s_alice_002" and blinding factor "r_alice_002"
    And Alice has computed a new commitment from these new values
    And Alice provides a proof of possession for the new commitment
    When Alice submits a rotation request with her proof of current commitment, the new commitment, and the new commitment's proof of possession
    Then the old commitment is replaced by the new commitment atomically
    And all active tokens issued under the old commitment are invalidated
    And a "CommitmentRotated" event is published containing the client identifier and the new commitment version
    And the rotation is recorded in the audit log
    And Alice's secret and blinding factor are zeroed from memory after the rotation proof is generated

  # --- Edge Cases ---

  Scenario: Rotation with same commitment value is rejected
    Given Alice submits a rotation request where the new commitment equals the current one
    When the rotation request is processed
    Then the rotation is refused
    And the reason indicates the new commitment must differ from the current one

  Scenario: Concurrent rotation requests are serialized via optimistic locking
    Given Alice sends two rotation requests simultaneously with different new commitments
    When both requests are processed
    Then exactly one rotation succeeds
    And the other is refused because the commitment version has changed since the request was initiated
    And the refused request does not corrupt the registry state

  Scenario: CommitmentRotated event invalidates pending challenges in Authentication Challenge context
    Given Alice has a pending challenge "challenge_abc" in the Authentication Challenge context
    When Alice successfully rotates her commitment
    And the "CommitmentRotated" event is consumed by the Authentication Challenge context
    Then the pending challenge "challenge_abc" is invalidated
    And any proof submitted against "challenge_abc" will be refused

  Scenario: Rotation during an ongoing proof verification (TOCTOU)
    Given Alice has submitted a proof that is currently being verified against her current commitment
    And Alice simultaneously submits a rotation request with a new commitment
    When the rotation completes before the verification finishes
    Then the in-flight verification is refused because the commitment has changed
    And the verification failure is recorded in the audit log
    And Alice can authenticate using a new challenge and proof against the new commitment

  Scenario: Revocation during an ongoing rotation
    Given Alice has submitted a rotation request that is currently being processed
    And administrator Bob revokes client "alice-payment-service" while the rotation is in progress
    When both operations complete
    Then the revocation takes precedence
    And Alice's client status is "revoked"
    And the rotation is refused or rolled back
    And the final state is consistent: revoked with no pending rotation artifacts

  Scenario: Event publisher failure after rotation does not leave partial state
    Given Alice submits a valid rotation request
    And the commitment replacement succeeds in the registry
    But the "CommitmentRotated" event publication fails due to infrastructure error
    When the failure is detected
    Then the entire rotation is rolled back
    And the old commitment is restored
    And Alice is informed the rotation failed and should be retried
    And the infrastructure failure is recorded in the audit log

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
    And the response timing is constant regardless of the refusal reason

  Scenario: Rotation rejected for locked-out client
    Given Alice's client is currently locked out due to failed authentication attempts
    When Alice submits a rotation request
    Then the rotation is refused
    And the lockout duration is not reset
    And the response is indistinguishable from other rotation failures

  Scenario: Rotation rejected when new commitment is the identity element
    Given Alice submits a rotation request with a new commitment that equals the identity element
    And the identity element is the Ristretto255 point encoding to 32 zero bytes
    When the rotation request is processed
    Then the rotation is refused
    And the reason indicates the new commitment is invalid

  Scenario: Rotation rejected when new commitment has non-canonical encoding
    Given Alice submits a rotation request with a new commitment that is not in the unique Ristretto255 32-byte compressed encoding
    When the rotation request is processed
    Then the rotation is refused
    And the reason indicates the encoding is invalid

  Scenario: Rate limiting on rotation requests
    Given Alice has exceeded the rotation rate limit threshold within the configured time window
    When Alice submits another rotation request
    Then the rotation is refused
    And the reason indicates rate limiting
    And the rejection is recorded in the audit log

  Scenario: Rotation rejected when service is at capacity for write operations
    Given the registry is currently unable to accept write operations due to capacity constraints
    When Alice submits a rotation request
    Then Alice's rotation is refused
    And the reason indicates the service is temporarily at capacity
    And Alice is advised to retry after a backoff period
```

---

## TDD Implementation Order

### Phase 1: Revocation Core
1. **RED**: Revocation changes client status to "revoked"
2. **RED**: Revocation requires authenticated administrator identity
3. **RED**: Revocation invalidates all active tokens
4. **RED**: Revocation invalidates all pending challenges
5. **RED**: Revocation is idempotent (already revoked client)
6. **RED**: Unknown client revocation is indistinguishable from success (constant-time)
7. **RED**: Revocation is permanent — no un-revoke path
8. **RED**: Unauthenticated revocation is rejected
9. **RED**: ClientRevoked domain event publication

### Phase 2: Rotation Core
10. **RED**: Rotation Fiat-Shamir transcript with domain separation tag "2FApi-v1.0-Rotation"
11. **RED**: Rotation requires valid proof of current commitment opening
12. **RED**: Rotation requires proof of possession for the new commitment
13. **RED**: Rotation replaces commitment atomically in registry
14. **RED**: Rotation invalidates all active tokens
15. **RED**: Same commitment rotation rejected
16. **RED**: Identity element as new commitment rejected
17. **RED**: Non-canonical encoding of new commitment rejected
18. **RED**: Rotation rejected for revoked / locked-out clients (constant-time response)

### Phase 3: Concurrency & Events
19. **RED**: Concurrent rotations serialized via optimistic locking
20. **RED**: CommitmentRotated event published with client identifier and version
21. **RED**: CommitmentRotated event consumed by Authentication Challenge to invalidate pending challenges
22. **RED**: Event publisher failure triggers full rotation rollback

### Phase 4: TOCTOU & Rate Limiting
23. **RED**: Revocation during ongoing proof verification — revocation wins
24. **RED**: Rotation during ongoing proof verification — rotation wins, old proof rejected
25. **RED**: Revocation during ongoing rotation — revocation takes precedence
26. **RED**: Rate limiting on rotation requests
27. **RED**: Rotation rejected when service at capacity for writes

### Phase 5: Audit & Compliance
28. **RED**: Audit logging for all lifecycle events (rotation, revocation, failures)
29. **RED**: Administrator identity recorded in all revocation audit entries
30. **RED**: Memory zeroization of secret material after rotation proof generation
