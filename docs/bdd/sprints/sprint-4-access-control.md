# Sprint 4 — API Access Control

> **Goal**: Authenticated clients receive audience-restricted tokens and can access protected resources.
> **Bounded Context**: API Access Control
> **Scenarios**: 17 | Happy: 4 | Edge: 6 | Error: 7
> **Prerequisites**: Sprint 3 (Verification — the full 2FA flow must work end-to-end)
> **Key deliverables**: Token issuance, audience restriction, step-up auth, resource access control

---

## Feature: Token Issuance

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

## Feature: Resource Access

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

## TDD Implementation Order

1. **RED**: Token creation with lifetime (15 min max), client binding, channel binding
2. **RED**: Token audience claim (restricted to specific service)
3. **RED**: Valid token → resource access granted
4. **RED**: Expired token → access denied
5. **RED**: Wrong audience → access denied (confused deputy)
6. **RED**: Wrong connection (channel binding mismatch) → access denied
7. **RED**: Forged token → constant-time rejection
8. **RED**: Token non-renewable → re-auth required
9. **RED**: Revocation invalidates active tokens immediately
10. **RED**: Step-up authentication for sensitive operations (elevated scope, reduced lifetime)
11. **RED**: Unauthenticated / malformed → rejection
12. **RED**: Audit logging for all access events
