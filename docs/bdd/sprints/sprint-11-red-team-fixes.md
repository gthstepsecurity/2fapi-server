# Sprint 11 — Red Team Audit Fixes

> **Goal**: Fix all 15 findings from the Red Team security audit. 7 already fixed in prior sprints; 8 remaining require code changes and new tests.
> **Bounded Contexts**: Client Registration, Authentication Challenge, Zero-Knowledge Verification, Security Monitoring, Shared
> **Scenarios**: 24 | Happy: 8 | Edge: 10 | Error: 6
> **Prerequisites**: Sprints 1-10 (all domain logic, verification, access control, hardening, REST API, pre-market audit fixes)
> **Audit reference**: Red Team security audit — 15 findings (1 critical, 2 high, 7 medium, 5 low)

---

## Findings Summary

| # | Severity | Title | Status |
|---|----------|-------|--------|
| 01 | MEDIUM | Dead code in Rust transcript (double SHA-512) | DONE |
| 02 | HIGH | Token audience mismatch — tokens unusable for resources | DONE |
| 03 | CRITICAL | Unauthenticated client revocation | DONE |
| 04 | MEDIUM | Lockout bypass after first expiry | DONE |
| 05 | MEDIUM | Enrollment idempotency leaks client existence via timing | TO FIX |
| 06 | HIGH | Rotation route audience mismatch (subset of #02) | DONE (with #02) |
| 07 | LOW | Rate limiter optional in enrollment and rotation | TO FIX |
| 08 | MEDIUM | Rotation rollback race condition | TO FIX |
| 09 | MEDIUM | Identity element not checked in Rust verify_equation | TO FIX |
| 10 | LOW | vartime multiscalar multiplication in proof generation | TO FIX |
| 11 | MEDIUM | TypeScript constant-time fallback is silent | TO FIX |
| 12 | LOW | Lockout threshold 3 with no exponential backoff | TO FIX |
| 13 | LOW | Hardcoded commitment version 2 | DONE |
| 14 | LOW | ChannelBinding.equals() early-returns on length | TO FIX |
| 15 | MEDIUM | Hardcoded audience "2fapi-default" creates token fungibility | DONE (with #02) |

---

## Feature 5: Enrollment Timing Oracle Mitigation (FINDING-05 — MEDIUM)

```gherkin
Feature: Enrollment Timing Oracle Mitigation
  As the authentication system
  I want idempotent enrollment to execute the same operations as new enrollment
  So that an attacker cannot determine client existence via response timing

  Background:
    Given the enrollment service is operational
    And a valid enrollment policy is configured

  # --- Happy Path ---

  Scenario: Idempotent enrollment executes save and publish like new enrollment
    Given Alice is already enrolled with commitment C
    When Alice enrolls again with the same commitment C
    Then the repository save() method is called (idempotent write)
    And the event publisher publish() method is called
    And the response is identical to the original enrollment response
    And the total number of operations matches a fresh enrollment

  # --- Edge Cases ---

  Scenario: New enrollment and idempotent enrollment call the same dependencies
    Given Alice is not yet enrolled
    When Alice enrolls for the first time
    Then save() is called exactly once
    And publish() is called exactly once
    When Alice enrolls again with the same commitment
    Then save() is called again (total: 2 calls)
    And publish() is called again (total: 2 calls)

  # --- Error Cases ---

  Scenario: Different commitment for existing identifier still rejected
    Given Alice is enrolled with commitment C1
    When Alice enrolls with a different commitment C2
    Then the enrollment is rejected with "enrollment_failed"
    And the rejection response shape is identical to all other failures
```

---

## Feature 7: Required Rate Limiter in Enrollment and Rotation (FINDING-07 — LOW)

```gherkin
Feature: Required Rate Limiter in Enrollment and Rotation
  As the security team
  I want the rate limiter to be a required dependency (not optional)
  So that forgetting to configure rate limiting is impossible in production

  Background:
    Given the enrollment and rotation use cases are configured

  # --- Happy Path ---

  Scenario: Enrollment use case requires rate limiter at construction
    Given a NoopRateLimiter is available as default
    When the EnrollClientUseCase is constructed with a rate limiter
    Then the rate limiter isAllowed() is called on every enrollment request
    And enrollment proceeds when the rate limiter allows it

  Scenario: Rotation use case requires rate limiter at construction
    Given a NoopRateLimiter is available as default
    When the RotateCommitmentUseCase is constructed with a rate limiter
    Then the rate limiter isAllowed() is called on every rotation request
    And rotation proceeds when the rate limiter allows it

  # --- Edge Cases ---

  Scenario: Rate limiter is always invoked even on allowed requests
    Given a rate limiter that allows all requests
    When a valid enrollment request is submitted
    Then the rate limiter isAllowed() is called exactly once
    And the enrollment succeeds

  # --- Error Cases ---

  Scenario: Rate limiter blocks enrollment
    Given a rate limiter that denies all requests
    When an enrollment request is submitted
    Then the enrollment fails with "enrollment_failed"
    And no save or event publish occurs
```

---

## Feature 8: Rotation Rollback Race Condition Fix (FINDING-08 — MEDIUM)

```gherkin
Feature: Rotation Rollback Race Condition Fix
  As the authentication system
  I want token and challenge invalidation to happen BEFORE event publishing
  So that a failed event publish can rollback all changes atomically

  Background:
    Given a registered active client with identifier "client-1"
    And the rotation policy accepts the request

  # --- Happy Path ---

  Scenario: Successful rotation executes operations in correct order
    When the client rotates their commitment successfully
    Then the operations execute in this order:
      | Step | Operation |
      | 1    | repository.update (save new commitment) |
      | 2    | tokenInvalidator.invalidateAllForClient |
      | 3    | challengeInvalidator.invalidateAllForClient |
      | 4    | eventPublisher.publish (CommitmentRotated) |
    And the audit log records "commitment_rotated"

  # --- Edge Cases ---

  Scenario: Event publisher failure triggers full rollback including invalidations
    Given the event publisher will fail
    When the client attempts to rotate their commitment
    Then the rotation fails with "rotation_failed"
    And the repository is rolled back to the original commitment
    And the token invalidation is undone (re-validated)
    And the challenge invalidation is undone (re-validated)

  Scenario: Token invalidation happens before event publish (not after)
    When the client rotates their commitment successfully
    Then tokens are invalidated before the event is published
    And challenges are invalidated before the event is published

  # --- Error Cases ---

  Scenario: Partial rollback on event publish failure is best-effort
    Given the event publisher will fail
    And the repository rollback will also fail
    When the client attempts to rotate their commitment
    Then the rotation still fails with "rotation_failed"
    And the audit log records "EVENT_PUBLISH_FAILED"
```

---

## Feature 9: Identity Element Check in Rust verify_equation (FINDING-09 — MEDIUM)

```gherkin
Feature: Identity Element Rejection in verify_equation
  As the cryptographic verification layer
  I want verify_equation to reject proofs with the identity element as announcement
  So that trivially forged proofs are detected and rejected

  Background:
    Given the Ristretto255 curve parameters are initialized

  # --- Happy Path ---

  Scenario: Valid proof with non-identity announcement is accepted
    Given a valid Sigma proof with a random announcement point
    When verify_equation is called with the proof components
    Then the verification returns true

  # --- Edge Cases ---

  Scenario: Proof with identity element as announcement is rejected
    Given a forged proof where the announcement A is the identity element (zero point)
    When verify_equation is called with the forged proof
    Then the verification returns false
    And the rejection occurs before the equation check

  # --- Error Cases ---

  Scenario: Identity announcement does not cause panic or undefined behavior
    Given the identity point as announcement
    And arbitrary scalar values for challenge, response_s, response_r
    When verify_equation is called
    Then it returns false without panicking
```

---

## Feature 10: Constant-Time Proof Generation (FINDING-10 — LOW)

```gherkin
Feature: Constant-Time Multiscalar Multiplication in Proof Generation
  As the cryptographic library
  I want proof generation to use constant-time operations
  So that secret scalars are not leaked via timing side channels

  Background:
    Given the Sigma proof module is compiled

  # --- Happy Path ---

  Scenario: prove() uses constant-time multiscalar_mul
    Given the prove() function source code
    When the announcement computation is inspected
    Then RistrettoPoint::multiscalar_mul is used (not vartime_multiscalar_mul)
    And the prover's secret randomness is protected from timing analysis

  Scenario: verify() keeps vartime for public inputs
    Given the verify() function source code
    When the LHS computation is inspected
    Then RistrettoPoint::vartime_multiscalar_mul is used (public inputs only)
    And performance is preserved for verification
```

---

## Feature 11: Constant-Time Fallback Warning (FINDING-11 — MEDIUM)

```gherkin
Feature: Constant-Time Fallback Warning
  As a production operator
  I want to be warned when the native constant-time module is unavailable
  So that I can detect and fix the misconfiguration before it becomes a vulnerability

  Background:
    Given the constant-time comparison utility is loaded

  # --- Happy Path ---

  Scenario: isNativeAvailable returns true when native module is loaded
    Given the native constant-time module is injected
    When isNativeAvailable() is called
    Then it returns true

  Scenario: isNativeAvailable returns false when native module is not loaded
    Given no native module is injected
    When isNativeAvailable() is called
    Then it returns false

  # --- Edge Cases ---

  Scenario: Fallback emits warning to stderr when warnOnFallback is enabled
    Given no native module is injected
    And warnOnFallback is enabled
    When constantTimeEqual is called
    Then a warning is emitted to stderr: "[2fapi] WARNING: using TypeScript fallback for constant-time comparison. Load the native Rust module for production security."
    And the comparison still returns the correct result

  Scenario: Fallback does not warn when warnOnFallback is disabled
    Given no native module is injected
    And warnOnFallback is not enabled
    When constantTimeEqual is called
    Then no warning is emitted to stderr
    And the comparison returns the correct result

  # --- Error Cases ---

  Scenario: Warning is emitted only once per process (not on every call)
    Given no native module is injected
    And warnOnFallback is enabled
    When constantTimeEqual is called 5 times
    Then the warning is emitted exactly once
```

---

## Feature 12: Exponential Backoff on Lockout (FINDING-12 — LOW)

```gherkin
Feature: Exponential Backoff on Lockout Duration
  As the security monitoring system
  I want lockout durations to increase exponentially on repeated lockouts
  So that persistent attackers face progressively longer delays

  Background:
    Given a lockout config with threshold 3, base duration 60 minutes, backoff multiplier 2, and max duration 24 hours

  # --- Happy Path ---

  Scenario: First lockout uses base duration
    Given a client with 0 prior lockouts
    When the client reaches the failure threshold for the first time
    Then the lockout duration is 60 minutes (base duration)

  Scenario: Second lockout doubles the duration
    Given a client who has been locked out once before
    When the client reaches the failure threshold again after reset
    Then the lockout duration is 120 minutes (60 * 2^1)

  Scenario: Third lockout quadruples the base duration
    Given a client who has been locked out twice before
    When the client reaches the failure threshold again
    Then the lockout duration is 240 minutes (60 * 2^2)

  # --- Edge Cases ---

  Scenario: Lockout duration is capped at maximum
    Given a client who has been locked out 10 times
    When the lockout duration would exceed 24 hours
    Then the lockout duration is capped at 24 hours (86400000 ms)

  Scenario: Backoff multiplier of 1 means no backoff (backward compatible)
    Given a lockout config with backoff multiplier 1
    When a client is locked out multiple times
    Then every lockout duration equals the base duration

  Scenario: Reset clears lockout count
    Given a client who has been locked out 3 times
    When the counter is reset (successful authentication)
    Then the lockout count returns to 0
    And the next lockout uses the base duration

  # --- Error Cases ---

  Scenario: Invalid backoff multiplier is rejected
    When creating a lockout config with backoff multiplier 0
    Then an error is thrown: "Backoff multiplier must be at least 1"

  Scenario: Invalid max duration is rejected
    When creating a lockout config with max duration 0
    Then an error is thrown: "Max duration must be positive"
```

---

## Feature 14: ChannelBinding Constant-Time Length Comparison (FINDING-14 — LOW)

```gherkin
Feature: ChannelBinding Constant-Time Length Comparison
  As the authentication challenge system
  I want ChannelBinding.equals() to not early-return on length mismatch
  So that timing side channels cannot reveal binding lengths

  Background:
    Given the ChannelBinding value object is available

  # --- Happy Path ---

  Scenario: Equal bindings are compared correctly
    Given two channel bindings with identical 32-byte values
    When equals() is called
    Then it returns true

  # --- Edge Cases ---

  Scenario: Different-length bindings compared without early return
    Given a 32-byte channel binding and a 48-byte channel binding
    When equals() is called
    Then it returns false
    And the comparison iterates over max(32, 48) = 48 bytes
    And no early return occurs on length mismatch

  Scenario: Length difference is folded into XOR accumulator
    Given a 32-byte binding and a 48-byte binding with identical prefix
    When equals() is called
    Then the length difference is XORed into the accumulator
    And the result is false regardless of byte content
```
