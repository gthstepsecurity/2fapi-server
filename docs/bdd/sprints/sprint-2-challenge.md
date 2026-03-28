# Sprint 2 — Authentication Challenge

> **Goal**: The server can issue fresh, unique, time-limited challenges to registered clients after credential verification.
> **Bounded Context**: Authentication Challenge
> **Scenarios**: 21 | Happy: 4 | Edge: 7 | Error: 10
> **Prerequisites**: Sprint 1 (Client Registration)
> **Key deliverables**: Challenge issuance, nonce uniqueness, expiry, first-factor credential verification

---

## Feature: Challenge Issuance

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

## Feature: Challenge Expiry

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

## Feature: Nonce Uniqueness Guarantee

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

## TDD Implementation Order

1. **RED**: Nonce generation (CSPRNG + monotonic counter)
2. **RED**: Nonce uniqueness guarantee (property-based test)
3. **RED**: First-factor credential verification
4. **RED**: Challenge issuance with nonce + channel binding + expiry
5. **RED**: Challenge stored in session store
6. **RED**: Previous pending challenge invalidation (single session)
7. **RED**: Challenge expiry (strictly less than TTL)
8. **RED**: Invalid credential → indistinguishable refusal
9. **RED**: Revoked / locked-out client → refusal
10. **RED**: Protocol version negotiation
11. **RED**: Legacy API key coexistence (migration)
12. **RED**: Counter overflow protection
13. **RED**: Audit logging for all challenge events
