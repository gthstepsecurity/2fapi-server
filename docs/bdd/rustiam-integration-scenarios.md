# BDD Scenarios — 2FApi Integration into RustIAM

> Generated from client specification on 2026-03-23
> Source: CEO directives + RustIAM architecture analysis

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| ZKP Enrollment | 3 | 18 | 5 | 6 | 7 |
| ZKP Authentication | 3 | 19 | 5 | 7 | 7 |
| Emergency Switch | 2 | 12 | 3 | 4 | 5 |
| Usage Metering & Billing | 2 | 12 | 3 | 5 | 4 |
| Administration | 2 | 10 | 3 | 4 | 3 |
| Recovery | 2 | 11 | 3 | 4 | 4 |
| Device Linking | 11 | 60 | 15 | 22 | 23 |
| **Total** | **25** | **142** | **37** | **52** | **53** |

> Device Linking scenarios are defined in [device-linking-scenarios.md](device-linking-scenarios.md)

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | New user | Register and enroll with ZKP authentication |
| Bob | Existing user | Authenticate using zero-knowledge proof |
| Carol | Tenant administrator | Configure 2FApi settings for her organization |
| Dave | Landlord (super-admin) | Manage platform-wide 2FApi settings and billing plans |
| Eve | Attacker | Attempt to authenticate without knowing the secret |
| System | RustIAM backend | Verify proofs, issue JWT tokens, meter usage |
| Frontend | RustIAM SPA | Generate proofs client-side via WASM SDK |

## Bounded Contexts

| Context | Ubiquitous Language (key terms) |
|---------|-------------------------------|
| ZKP Enrollment | commitment, secret, blinding, recovery phrase, enrollment, proof of possession |
| ZKP Authentication | challenge, nonce, proof, verification, session, JWT |
| Emergency Switch | authentication mode, password fallback, switch, password reset invitation |
| Usage Metering & Billing | verification request, daily quota, plan, overage, billing cycle |
| Administration | platform settings, recovery word count, authentication mode, plan configuration |
| Recovery | recovery phrase, re-enrollment, secret restoration, account recovery |

## Hypotheses

> These assumptions were made where the spec was silent or ambiguous.
> **Review and validate before proceeding.**

1. 2FApi replaces the password entirely — the user never types a password when 2FApi is active
2. The Pedersen commitment is generated client-side (WASM) and only the commitment (public) is sent to the server — the secret never leaves the browser
3. Recovery phrases follow BIP-39 standard (12, 15, 18, 21, or 24 words) — the admin configures the word count
4. The emergency switch from 2FApi → password mode triggers an email to all affected users with a password reset link
5. Usage metering counts verification requests (not enrollments or challenges) — per-tenant, per-day
6. The billing plans (Free/Pro/Enterprise) are configurable by the Landlord in platform settings
7. When the platform switches back from password → 2FApi mode, users who already have a commitment resume normally; users without one must enroll at next login
8. The WASM client SDK is loaded lazily (only on auth pages) to minimize bundle size impact
9. The crypto-core Rust crate is integrated as a workspace dependency in RustIAM's Cargo.toml — no FFI boundary
10. Challenge nonces are stored in Redis with 120-second TTL, same infrastructure as existing 2FA sessions

---

## ZKP Enrollment

### Feature: User enrollment with Pedersen commitment

  As a new user (Alice)
  I want to enroll with a zero-knowledge proof credential
  So that I can authenticate without the server ever knowing my secret

  Background:
    Given the platform "Acme Corp" has 2FApi authentication enabled
    And the recovery phrase length is configured to 12 words

  # --- Happy Path ---

  Scenario: Successful enrollment during registration
    Given Alice is on the registration page for "Acme Corp"
    When Alice fills in her name "Alice Martin" and email "alice@acme.com"
    And Alice confirms her registration
    Then the system generates a secret and blinding factor in Alice's browser
    And the system computes a Pedersen commitment from the secret
    And the system sends the commitment and a proof of possession to the server
    And the server verifies the proof opens the commitment
    And Alice's commitment is stored in the enrollment registry
    And Alice is shown 12 recovery words
    And Alice must confirm she has saved the recovery words
    And Alice receives a confirmation that enrollment is complete

  Scenario: Successful enrollment at first login for pre-existing user
    Given Bob was created before 2FApi was enabled on "Acme Corp"
    And Bob has no commitment registered
    When Bob navigates to the login page
    Then the system detects Bob has no commitment
    And Bob is guided through the enrollment process
    And Bob's commitment is stored after successful proof verification
    And Bob is shown 12 recovery words
    And Bob is logged in after confirming the recovery words

  # --- Business Rule Variations ---

  Scenario: Recovery phrase length varies by platform configuration
    Given the platform "SecureCo" has recovery phrase length set to 24 words
    When Alice enrolls on "SecureCo"
    Then Alice is shown exactly 24 recovery words

  Scenario Outline: Recovery phrase word count must be a valid BIP-39 length
    Given the Landlord configures recovery phrase length to <word_count> words
    Then the configuration is <result>

    Examples:
      | word_count | result   |
      | 12         | accepted |
      | 15         | accepted |
      | 18         | accepted |
      | 21         | accepted |
      | 24         | accepted |
      | 10         | rejected |
      | 13         | rejected |
      | 0          | rejected |

  # --- Edge Cases ---

  Scenario: Enrollment interrupted before recovery words are confirmed
    Given Alice has submitted her commitment successfully
    And Alice is viewing her 12 recovery words
    When Alice closes her browser before confirming
    Then Alice's enrollment is marked as incomplete
    And Alice must complete enrollment at her next login attempt

  Scenario: Enrollment with browser that does not support WASM
    Given Alice uses a browser without WebAssembly support
    When Alice attempts to register on "Acme Corp"
    Then Alice sees a message explaining that a modern browser is required
    And the enrollment does not proceed

  # --- Error Cases ---

  Scenario: Enrollment rejected when commitment is the identity element
    Given Alice's browser produces an invalid commitment (all zeros)
    When the server receives the enrollment request
    Then the server rejects the enrollment
    And Alice sees an error asking her to retry

  Scenario: Enrollment rejected when proof of possession is invalid
    Given Eve intercepts Alice's commitment and submits a forged proof
    When the server verifies the proof against the commitment
    Then the server rejects the enrollment
    And the attempt is logged in the audit trail

  Scenario: Duplicate enrollment for same email is rejected
    Given Alice is already enrolled on "Acme Corp"
    When someone attempts to enroll with "alice@acme.com" again
    Then the system responds identically to a successful enrollment
    And no data is modified (anti-enumeration protection)

  Scenario: Enrollment fails when server is unreachable
    Given Alice has generated her commitment in the browser
    When the browser attempts to send the commitment to the server
    And the server is unreachable
    Then Alice sees a network error message
    And Alice can retry without regenerating her secret

---

### Feature: Commitment storage and lifecycle

  As the system
  I want to store commitments securely
  So that they can be used for future authentication

  Scenario: Commitment is stored in the enrollment registry
    Given Alice has successfully enrolled
    Then a record exists in the enrollment registry with Alice's user identifier
    And the record contains a 32-byte Pedersen commitment
    And the record status is "active"
    And the record includes a creation timestamp

  Scenario: Only one active commitment per user
    Given Alice has an active commitment
    When Alice re-enrolls (e.g., after recovery)
    Then the previous commitment is replaced by the new one
    And the commitment version is incremented
    And the previous commitment is archived in the audit trail

---

## ZKP Authentication

### Feature: Zero-knowledge proof authentication

  As an enrolled user (Bob)
  I want to prove I know my secret without revealing it
  So that I can access my account securely

  Background:
    Given the platform "Acme Corp" has 2FApi authentication enabled
    And Bob is enrolled with an active commitment

  # --- Happy Path ---

  Scenario: Successful authentication with valid proof
    Given Bob navigates to the login page
    And Bob enters his email "bob@acme.com"
    When Bob's browser requests a challenge from the server
    Then the server issues a fresh nonce bound to Bob's account
    And Bob's browser computes a Sigma proof using the secret and the nonce
    And Bob's browser sends the proof to the server
    And the server verifies the proof against Bob's stored commitment
    And the challenge is consumed (single-use)
    And Bob receives a JWT access token
    And Bob is redirected to his dashboard

  Scenario: Challenge expires after 2 minutes
    Given Bob requested a challenge 3 minutes ago
    When Bob submits his proof
    Then the server rejects the proof because the challenge has expired
    And Bob must request a new challenge

  # --- Business Rule Variations ---

  Scenario: Authentication populates JWT with standard claims
    Given Bob authenticates successfully
    Then the JWT contains Bob's user identifier as subject
    And the JWT contains Bob's tenant identifier
    And the JWT contains Bob's role
    And the JWT is signed with the platform's secret key
    And the JWT expiration matches the platform configuration

  Scenario: Successful authentication updates last login timestamp
    Given Bob authenticates successfully at "2026-03-23 10:30:00"
    Then Bob's last login timestamp is updated to "2026-03-23 10:30:00"
    And an authentication event is recorded in the audit trail

  # --- Edge Cases ---

  Scenario: Challenge is consumed even if proof is invalid
    Given Bob requests a challenge "ch-abc123"
    When Eve submits an invalid proof for challenge "ch-abc123"
    Then the challenge "ch-abc123" is permanently consumed
    And Eve receives a generic "authentication failed" message
    And Bob must request a new challenge if he wants to authenticate

  Scenario: Concurrent challenge requests for the same user
    Given Bob requests two challenges simultaneously
    Then both challenges are issued with different nonces
    And only one can be used for authentication (first verified wins)

  Scenario: User with suspended account attempts authentication
    Given Bob's account status is "suspended"
    When Bob attempts to request a challenge
    Then the server refuses to issue a challenge
    And Bob sees a message explaining his account is suspended

  # --- Error Cases ---

  Scenario: Authentication with non-existent email
    Given no user is registered with "unknown@acme.com"
    When someone enters "unknown@acme.com" on the login page
    Then the response is indistinguishable from a valid user response
    And no challenge is actually created (anti-enumeration)

  Scenario: Authentication with revoked commitment
    Given Bob's commitment has been revoked by an administrator
    When Bob attempts to authenticate
    Then the server rejects the authentication
    And Bob is guided to re-enroll or contact support

  Scenario: Proof verification fails due to wrong secret
    Given Eve knows Bob's email but not his secret
    When Eve submits a proof computed with a random secret
    Then the Sigma equation check fails
    And Eve receives a generic "authentication failed" message
    And the attempt is logged with Eve's IP address

  Scenario: Rate limiting on failed authentication attempts
    Given someone has failed authentication for "bob@acme.com" 5 times in 10 minutes
    When they attempt a 6th authentication
    Then the server rejects the request with a rate limit message
    And the lockout duration is 15 minutes

---

### Feature: Multi-tenant authentication isolation

  As the system
  I want each tenant's authentication to be isolated
  So that one tenant's users cannot access another tenant's data

  Scenario: User commitment is scoped to tenant
    Given Alice is enrolled on tenant "Acme Corp"
    And Alice is NOT enrolled on tenant "Other Corp"
    When Alice attempts to authenticate on "Other Corp"
    Then the authentication fails because no commitment exists
    And Alice's "Acme Corp" commitment is never consulted

  Scenario: Challenge is scoped to tenant
    Given Bob requests a challenge on tenant "Acme Corp"
    When someone attempts to use that challenge on tenant "Other Corp"
    Then the verification fails because the challenge does not exist in that tenant

---

## Emergency Switch

### Feature: Switch from 2FApi to password authentication

  As a Tenant administrator (Carol)
  I want to switch the platform from 2FApi to password mode in an emergency
  So that users can still access their accounts if 2FApi has an issue

  Background:
    Given tenant "Acme Corp" currently uses 2FApi authentication
    And Carol is a tenant administrator for "Acme Corp"

  # --- Happy Path ---

  Scenario: Administrator switches to password mode
    Given Carol navigates to the authentication settings
    When Carol activates the emergency switch to password mode
    And Carol confirms the switch with her admin credentials
    Then the platform authentication mode changes to "password"
    And all active 2FApi sessions remain valid until expiration
    And a password reset invitation is sent to all users without a password
    And an audit event "authentication_mode_switched" is recorded

  Scenario: Users receive password reset invitation after switch
    Given the platform has switched from 2FApi to password mode
    And Alice never had a password (enrolled directly with 2FApi)
    Then Alice receives an email with a password reset link
    And the link is valid for 72 hours
    And Alice can set a new password using the link
    And Alice can then log in with email and password

  # --- Edge Cases ---

  Scenario: User who already has a password can log in immediately after switch
    Given Bob had a password before 2FApi was enabled
    And the platform switches to password mode
    When Bob navigates to the login page
    Then Bob sees the email/password login form
    And Bob can authenticate with his existing password

  Scenario: Switch back from password to 2FApi mode
    Given the platform is in password mode
    When Carol switches back to 2FApi mode
    Then users with existing commitments authenticate via 2FApi immediately
    And users without commitments are guided to enroll at next login
    And no password reset is needed

  # --- Error Cases ---

  Scenario: Non-administrator cannot switch authentication mode
    Given Bob is a regular user (not administrator)
    When Bob attempts to access the authentication mode settings
    Then Bob is denied access
    And the attempt is logged in the audit trail

  Scenario: Switch requires confirmation to prevent accidental activation
    Given Carol clicks the emergency switch toggle
    When Carol does not confirm within 30 seconds
    Then the switch is cancelled
    And the authentication mode remains unchanged

  Scenario: Switch fails if email service is unavailable
    Given the email service is down
    When Carol attempts to switch to password mode
    Then the switch is rejected with a warning
    And the reason is "cannot send password reset emails to users"
    And the authentication mode remains 2FApi

---

### Feature: Switch audit and monitoring

  As the Landlord (Dave)
  I want to monitor authentication mode changes across all tenants
  So that I can detect unauthorized switches and ensure platform stability

  Scenario: All switches are logged in the platform audit trail
    Given Carol switches "Acme Corp" from 2FApi to password mode
    Then the audit trail records the switch timestamp
    And the audit trail records Carol's user identifier
    And the audit trail records the source IP address
    And the audit trail records the previous and new authentication modes

  Scenario: Landlord receives notification on emergency switch
    Given Carol switches "Acme Corp" to password mode
    Then Dave receives a notification about the switch
    And the notification includes the tenant name and administrator who switched

  Scenario: Switch history is visible in the administration dashboard
    Given "Acme Corp" has switched modes 3 times in the last month
    When Dave views the authentication mode history for "Acme Corp"
    Then Dave sees 3 entries with timestamps, actors, and modes

  Scenario: Rapid switching is rate-limited
    Given Carol switches to password mode
    When Carol immediately tries to switch back to 2FApi mode
    Then the switch is rejected with a cooldown message of 5 minutes
    And the reason is "authentication mode changes are rate-limited for security"

  Scenario: Landlord can force authentication mode for a tenant
    Given the Landlord Dave decides "Acme Corp" must use 2FApi
    When Dave sets the authentication mode override to "2FApi enforced"
    Then Carol can no longer switch to password mode
    And Carol sees a message "Authentication mode is managed by the platform administrator"

---

## Usage Metering & Billing

### Feature: Verification request counting

  As the system
  I want to count verification requests per tenant per day
  So that usage can be billed according to the tenant's plan

  Background:
    Given tenant "Acme Corp" is on the "Free" plan with 100 verifications per day

  # --- Happy Path ---

  Scenario: Verification request increments daily counter
    Given "Acme Corp" has used 42 verifications today
    When Bob authenticates successfully
    Then the daily counter for "Acme Corp" is 43

  Scenario: Counter resets at midnight UTC
    Given "Acme Corp" has used 99 verifications on March 22
    When the clock passes midnight UTC to March 23
    Then the daily counter for "Acme Corp" resets to 0

  # --- Edge Cases ---

  Scenario: Failed verification also counts toward quota
    Given "Acme Corp" has used 99 verifications today
    When Eve submits an invalid proof
    Then the daily counter for "Acme Corp" is 100
    And the verification is denied (both for invalid proof and quota reasons)

  Scenario: Quota exceeded returns specific error
    Given "Acme Corp" has used 100 verifications today (quota reached)
    When Bob attempts to authenticate
    Then Bob sees a message "Daily authentication limit reached, please try again tomorrow"
    And the verification request is not processed (no cryptographic computation wasted)

  Scenario: Enrollment requests do not count toward quota
    Given "Acme Corp" has used 99 verifications today
    When Alice enrolls (submits commitment + proof of possession)
    Then the daily counter remains 99
    And Alice's enrollment succeeds

  # --- Error Cases ---

  Scenario: Counter service unavailable does not block authentication
    Given the metering service (Redis counter) is temporarily unavailable
    When Bob attempts to authenticate
    Then Bob's authentication proceeds normally (fail-open for metering)
    And a warning is logged for the operations team
    And the counter is reconciled when the service recovers

  Scenario: Tenant with no plan defaults to free tier
    Given "NewCo" has no billing plan configured
    When a user on "NewCo" authenticates
    Then the free tier limit of 100 verifications per day applies

---

### Feature: Billing plan configuration

  As the Landlord (Dave)
  I want to configure billing plans with verification quotas
  So that tenants can choose a plan that fits their usage

  Scenario: Landlord creates a billing plan
    Given Dave navigates to the billing plan administration
    When Dave creates a plan named "Pro" with 100000 daily verifications at 300 EUR per month
    Then the plan "Pro" is available for tenants to subscribe to
    And the plan appears in the public pricing page

  Scenario: Tenant upgrades from Free to Pro
    Given "Acme Corp" is on the "Free" plan
    When Carol upgrades to the "Pro" plan
    Then the daily verification limit increases to 100000 immediately
    And billing begins for the current month (prorated)

  Scenario: Default plans exist at platform initialization
    Given the platform is freshly installed
    Then three default plans exist: "Free" (100/day, 0 EUR), "Pro" (100000/day, 300 EUR), "Enterprise" (unlimited, custom pricing)

  Scenario Outline: Plan quota enforcement
    Given tenant "TestCo" is on the "<plan>" plan
    And "TestCo" has used <used> verifications today
    When a user attempts to authenticate
    Then the result is "<outcome>"

    Examples:
      | plan       | used   | outcome                  |
      | Free       | 99     | authentication proceeds  |
      | Free       | 100    | quota exceeded           |
      | Pro        | 99999  | authentication proceeds  |
      | Pro        | 100000 | quota exceeded           |
      | Enterprise | 999999 | authentication proceeds  |

  Scenario: Landlord modifies plan quota
    Given the "Pro" plan has a limit of 100000 daily verifications
    When Dave changes the limit to 200000
    Then all tenants on the "Pro" plan immediately benefit from the new limit

---

## Administration

### Feature: Platform-wide 2FApi configuration

  As the Landlord (Dave)
  I want to configure 2FApi settings for the entire platform
  So that all tenants benefit from consistent security policies

  Scenario: Landlord configures recovery phrase word count
    Given Dave navigates to platform security settings
    When Dave sets the recovery phrase length to 24 words
    Then all new enrollments across all tenants use 24-word recovery phrases
    And existing enrollments are not affected

  Scenario: Landlord views platform-wide authentication statistics
    Given the platform has 50 tenants with 2FApi enabled
    When Dave views the authentication dashboard
    Then Dave sees total daily verifications across all tenants
    And Dave sees a breakdown by tenant
    And Dave sees the success/failure ratio
    And Dave sees the average verification latency

  Scenario: Landlord configures challenge TTL
    Given the default challenge TTL is 120 seconds
    When Dave changes the challenge TTL to 60 seconds
    Then all new challenges expire after 60 seconds
    And existing challenges retain their original TTL

  # --- Edge Cases ---

  Scenario: Configuration changes are audited
    Given Dave changes the recovery phrase length from 12 to 24
    Then an audit event is recorded with the previous and new values
    And the event includes Dave's user identifier and timestamp

  Scenario: Invalid configuration is rejected
    Given Dave attempts to set the challenge TTL to 0 seconds
    Then the system rejects the configuration
    And Dave sees a validation error "Challenge TTL must be between 10 and 300 seconds"

---

### Feature: Tenant-level 2FApi administration

  As a Tenant administrator (Carol)
  I want to view 2FApi usage for my organization
  So that I can monitor adoption and detect anomalies

  Scenario: Administrator views tenant enrollment status
    Given "Acme Corp" has 50 users, 45 enrolled with 2FApi
    When Carol views the 2FApi dashboard
    Then Carol sees 45 enrolled and 5 pending enrollment
    And Carol can see which users have not yet enrolled

  Scenario: Administrator views daily verification usage
    Given "Acme Corp" is on the "Pro" plan with 100000 daily limit
    And 4523 verifications have been used today
    When Carol views the usage dashboard
    Then Carol sees "4523 / 100000 verifications used today (4.5%)"

  Scenario: Administrator exports enrollment report
    Given Carol requests an enrollment report
    Then the system generates a report with user names, enrollment dates, and status
    And the report does NOT include commitments or recovery phrases

  Scenario: Approaching quota triggers notification
    Given "Acme Corp" is on the "Free" plan (100 verifications/day)
    And 80 verifications have been used today
    Then Carol receives a notification "80% of daily quota used"
    And the notification suggests upgrading to the Pro plan

  Scenario: Administrator cannot see user secrets or recovery phrases
    Given Carol is a tenant administrator
    When Carol views Alice's enrollment details
    Then Carol sees the enrollment date and status
    And Carol does NOT see Alice's commitment bytes
    And Carol does NOT see Alice's recovery words

---

## Recovery

### Feature: Account recovery via recovery phrase

  As an enrolled user (Bob)
  I want to recover my account using my recovery phrase
  So that I can regain access if I lose my device or secret

  Background:
    Given Bob is enrolled on "Acme Corp" with an active commitment
    And Bob was given 12 recovery words at enrollment

  # --- Happy Path ---

  Scenario: Successful account recovery with correct phrase
    Given Bob has lost access to his secret
    When Bob navigates to the account recovery page
    And Bob enters his email "bob@acme.com"
    And Bob enters all 12 recovery words correctly
    Then the system derives Bob's original secret from the recovery phrase
    And the system verifies the derived secret matches Bob's stored commitment
    And Bob is guided through a new enrollment (new secret, new commitment)
    And Bob receives new recovery words
    And Bob's old commitment is replaced by the new one
    And Bob is logged in with a new session

  Scenario: Recovery phrase verification is done client-side
    Given Bob enters his 12 recovery words
    Then the secret derivation happens entirely in Bob's browser (WASM)
    And the recovery phrase is never sent to the server
    And only the new commitment and proof are sent to the server

  # --- Edge Cases ---

  Scenario: Partial recovery phrase is rejected
    Given Bob enters only 11 of his 12 recovery words
    When Bob submits the recovery form
    Then the system rejects the attempt
    And Bob sees "Please enter all 12 recovery words"

  Scenario: Recovery with correct words in wrong order
    Given Bob enters all 12 words but in the wrong order
    When Bob submits the recovery form
    Then the derived secret does not match the stored commitment
    And Bob sees "Recovery phrase is incorrect"
    And the attempt is logged in the audit trail

  Scenario: Recovery is rate-limited
    Given someone has attempted recovery for "bob@acme.com" 3 times in 1 hour
    When they attempt a 4th recovery
    Then the attempt is rejected with a rate limit message
    And Bob's account is temporarily locked for recovery attempts

  Scenario: Recovery works after emergency switch back to 2FApi
    Given "Acme Corp" switched to password mode and back to 2FApi
    And Bob's commitment is still active
    When Bob has forgotten his secret
    Then Bob can use his original recovery phrase to re-enroll

  # --- Error Cases ---

  Scenario: Recovery for non-existent user
    Given no user exists with email "ghost@acme.com"
    When someone attempts recovery for "ghost@acme.com"
    Then the response is indistinguishable from a valid user response
    And no recovery is actually processed (anti-enumeration)

  Scenario: Recovery for user with no commitment
    Given Dave was created before 2FApi was enabled
    And Dave has no commitment registered
    When Dave attempts account recovery
    Then the system tells Dave to use the standard enrollment process instead

  Scenario: Recovery blocked for suspended account
    Given Bob's account is suspended
    When Bob attempts recovery
    Then the recovery is rejected
    And Bob sees "Your account is suspended, please contact support"

---

### Feature: Recovery phrase security

  As the system
  I want recovery phrases to be handled securely
  So that they cannot be intercepted or leaked

  Scenario: Recovery phrase is shown only once during enrollment
    Given Alice has just enrolled
    And Alice is viewing her 12 recovery words
    When Alice confirms she has saved the words
    Then the recovery words are never displayed again
    And the server does not store the recovery words

  Scenario: Recovery phrase derivation uses Argon2id
    Given Bob enters his 12 recovery words for account recovery
    Then the client derives the secret using Argon2id with a deterministic salt
    And the derivation takes at least 500ms (anti-brute-force)
    And the derived secret is used to verify against the stored commitment
