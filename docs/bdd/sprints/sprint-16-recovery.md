# Sprint 16 — Recovery Mechanisms

> **Goal**: Suspended clients can recover access autonomously via a BIP-39 recovery phrase, or through external intervention by an administrator. Recovery always requires a new commitment — the old secret is considered compromised.
> **Bounded Context**: Client Registration (recovery lifecycle), Security Monitoring (recovery audit)
> **Scenarios**: 35 | Happy: 8 | Edge: 14 | Error: 13
> **Prerequisites**: Sprint 15 (Compromise Detection — suspended client state and ClientSuspended event), Sprint 1 (Enrollment — commitment registration), Sprint 6 (Lifecycle — revocation state)
> **Key deliverables**: BIP-39 recovery phrase generation, Argon2id-based phrase verification, phrase recovery flow, external reactivation flow, recovery configuration, security hardening

### Design Decisions

**1. Recovery phrase is generated at enrollment time only**
- 12, 18, or 24 words from the BIP-39 English wordlist (2048 words).
- Words are displayed exactly once in the enrollment response and never stored server-side.
- A recovery key is derived from the words, hashed with Argon2id, and the hash is stored alongside the client record.
- The phrase cannot be retrieved, regenerated, or displayed again after enrollment.

**2. Argon2id parameters**
- Salt = `"mnemonic" + clientIdentifier` (following BIP-39 convention).
- Default parameters: memory 64 MB, iterations 3, parallelism 4.
- Parameters are configurable per operator but only apply to new enrollments.
- Argon2id is inherently slow, providing natural timing-safe comparison.

**3. Recovery always requires a new commitment**
- Whether recovering via phrase or external intervention, the client MUST provide a new (s, r) and new commitment.
- The old secret is considered compromised. Old tokens, challenges, and commitments are invalidated.
- The client identifier remains the same; only the cryptographic material changes.

**4. Recovery lockout after 3 failed attempts**
- 3 incorrect phrase submissions lock the recovery path permanently.
- After lockout, only an administrator can reactivate the client (Mode 1).
- The lockout counter is reset on successful recovery or successful external reactivation.

**5. Recovery modes are operator-configurable**
- `"phrase_only"`: Only BIP-39 phrase recovery is available.
- `"external_only"`: Only external intervention recovery is available.
- `"phrase_and_external"` (default): Phrase first, external as fallback if words are lost.
- Configuration changes apply only to new enrollments.

---

## Feature: Recovery Phrase Generation (BIP-39)

```gherkin
Feature: Recovery Phrase Generation (BIP-39)
  As the authentication system
  I want to generate a BIP-39 recovery phrase at client enrollment
  So that a suspended client can autonomously recover access without administrator intervention

  Background:
    Given the authentication service is operational
    And recovery mode is configured as "phrase_and_external"
    And the recovery word count is configured as 12

  # --- Happy Path ---

  Scenario: At enrollment, 12 recovery words generated from BIP-39 English wordlist
    When Alice enrolls with client identifier "alice-payment-service" and a valid commitment
    Then the enrollment response includes exactly 12 recovery words
    And each word belongs to the BIP-39 English wordlist of 2048 words
    And the words are generated from a cryptographically secure random source

  Scenario: Words displayed exactly once in enrollment response
    When Alice enrolls with client identifier "alice-payment-service" and a valid commitment
    Then the enrollment response includes the 12 recovery words
    And no subsequent API call can retrieve the recovery words
    And no endpoint exists to display or resend the recovery words

  Scenario: Recovery key derived from words via Argon2id
    Given Alice enrolls and receives recovery words "abandon ability able about above absent absorb abstract absurd abuse access accident"
    When the system derives the recovery key
    Then the derivation uses Argon2id as the key derivation function
    And the derivation result is a fixed-length hash

  Scenario: Salt follows BIP-39 convention
    Given Alice enrolls with client identifier "alice-payment-service"
    When the system derives the recovery key from the words
    Then the salt used is "mnemonic" concatenated with "alice-payment-service"
    And the salt is encoded as UTF-8 bytes

  Scenario: Argon2id parameters match configured defaults
    When Alice enrolls and the recovery key is derived
    Then the Argon2id parameters are: memory 65536 KB (64 MB), iterations 3, parallelism 4
    And the output hash length is 32 bytes

  # --- Edge Cases ---

  Scenario: Recovery key hash stored alongside client record
    When Alice enrolls with client identifier "alice-payment-service"
    Then the client record in the registry includes the Argon2id hash of the recovery key
    And the client record does NOT include the recovery words
    And the client record does NOT include the plaintext recovery key

  Scenario: Words are NOT stored server-side
    When Alice enrolls and the enrollment response is returned
    Then the recovery words exist only in the enrollment response payload
    And the server retains only the Argon2id hash
    And no server-side storage contains the words or the intermediate recovery key
    And the intermediate recovery key is zeroized from memory after hashing

  # --- Error Cases ---

  Scenario: Word count configurable by operator
    Given operator "standard" has configured word count as 12
    And operator "high-security" has configured word count as 24
    When a client enrolls under operator "standard"
    Then the enrollment response includes exactly 12 words (128 bits of entropy)
    When a client enrolls under operator "high-security"
    Then the enrollment response includes exactly 24 words (256 bits of entropy)
```

## Feature: Recovery via Phrase (Mode 3)

```gherkin
Feature: Recovery via Phrase (Mode 3)
  As a suspended client
  I want to recover access by providing my BIP-39 recovery phrase
  So that I can autonomously re-establish authentication without administrator intervention

  Background:
    Given the authentication service is operational
    And recovery mode is configured as "phrase_and_external"
    And Alice was enrolled with client identifier "alice-payment-service"
    And Alice received recovery words "abandon ability able about above absent absorb abstract absurd abuse access accident"
    And Alice's client status is "suspended" due to a detected anomaly

  # --- Happy Path ---

  Scenario: Suspended client provides correct 12 words and recovery is authorized
    When Alice submits a recovery request with words "abandon ability able about above absent absorb abstract absurd abuse access accident"
    And Alice provides a new commitment computed from new secret values
    Then the system derives the recovery key from the provided words using Argon2id
    And the derived hash matches the stored recovery key hash
    And the recovery is authorized

  Scenario: Recovery requires new commitment — old secret considered compromised
    When Alice submits a valid recovery request with correct words
    Then Alice MUST provide a new commitment (new s, r values)
    And the old commitment is replaced by the new commitment
    And the old secret is considered permanently compromised
    And all old tokens and challenges are invalidated

  Scenario: Recovery generates new enrollment receipt with same identifier
    When Alice successfully recovers with correct words and a new commitment
    Then a new enrollment receipt is generated
    And the receipt uses the same client identifier "alice-payment-service"
    And the receipt contains the new commitment
    And new recovery words are generated and displayed exactly once
    And a new Argon2id hash is stored for the new recovery words

  Scenario: Recovery resets failed attempt counter and lockout
    Given Alice had 2 failed recovery attempts before providing correct words
    When Alice submits a valid recovery request with correct words and a new commitment
    Then the failed recovery attempt counter is reset to 0
    And any lockout timer is cleared
    And Alice's client status is changed to "active"

  Scenario: Recovery publishes ClientRecovered event
    When Alice successfully recovers with correct words and a new commitment
    Then a "ClientRecovered" event is published
    And the event includes client identifier "alice-payment-service"
    And the event includes the recovery method "phrase"
    And the event includes the recovery timestamp
    And the recovery is recorded in the audit log

  # --- Edge Cases ---

  Scenario: Recovery on a non-suspended client is refused
    Given Alice's client status is "active"
    When Alice submits a recovery request with correct words
    Then the recovery is refused
    And the response is indistinguishable from an incorrect words response
    And the response timing is constant regardless of the refusal reason

  Scenario: Recovery on a revoked client is refused
    Given Alice's client status is "revoked"
    When Alice submits a recovery request with correct words
    Then the recovery is refused
    And the response is indistinguishable from an incorrect words response
    And the response timing is constant regardless of the refusal reason

  # --- Error Cases ---

  Scenario: Incorrect words result in recovery refusal with indistinguishable response
    When Alice submits a recovery request with words "zoo zone zero year wrong write world wonder witness window winter wild"
    Then the recovery is refused
    And the failed recovery attempt counter increments to 1
    And the response body is identical to a non-suspended client recovery refusal
    And the response timing is indistinguishable from other refusal reasons

  Scenario: 3 failed recovery attempts locks recovery permanently
    Given Alice has 2 failed recovery attempts
    When Alice submits a recovery request with incorrect words
    Then the failed recovery attempt counter increments to 3
    And the recovery path is permanently locked for client "alice-payment-service"
    And a "RecoveryLocked" event is published
    And further recovery attempts via phrase are refused
    And only administrator intervention (Mode 1) can reactivate the client

  Scenario: Recovery locked client response is indistinguishable from other failures
    Given Alice's recovery path is locked after 3 failed attempts
    When Alice submits a recovery request with any words (correct or incorrect)
    Then the response is identical to an incorrect words response
    And the response timing is constant
    And no information about the lockout status is leaked to the client
```

## Feature: Recovery via External Intervention (Mode 1)

```gherkin
Feature: Recovery via External Intervention (Mode 1)
  As an administrator of an external identity verification system
  I want to reactivate a suspended 2FApi client after verifying their identity externally
  So that clients who lost their recovery phrase can regain access

  Background:
    Given the authentication service is operational
    And recovery mode is configured as "phrase_and_external" or "external_only"
    And Alice is registered with client identifier "alice-payment-service"
    And Alice's client status is "suspended"

  # --- Happy Path ---

  Scenario: ClientSuspended event published with reason for external system
    Given Alice was auto-suspended with reason "concurrent_session"
    Then a "ClientSuspended" event was published
    And the event includes client identifier "alice-payment-service"
    And the event includes reason "concurrent_session"
    And the event includes the suspension timestamp
    And the external identity verification system can consume this event

  Scenario: External system calls reactivation endpoint with admin credentials
    Given administrator Bob has verified Alice's identity through an external process
    When Bob calls the reactivation endpoint for client "alice-payment-service"
    And Bob authenticates with admin identity "bob-admin-id"
    And Bob provides a new commitment on behalf of Alice
    Then Alice's client status is changed to "active"
    And the old commitment is replaced by the new commitment
    And all old tokens and challenges are invalidated

  Scenario: Reactivation publishes ClientReactivated event
    When administrator Bob successfully reactivates client "alice-payment-service"
    Then a "ClientReactivated" event is published
    And the event includes client identifier "alice-payment-service"
    And the event includes administrator identity "bob-admin-id"
    And the event includes the reactivation method "external_intervention"
    And the reactivation is recorded in the audit log with Bob's identity

  Scenario: Reactivation resets suspension state, failed attempts, and lockout
    Given Alice had 3 failed recovery attempts and recovery was locked
    When administrator Bob successfully reactivates client "alice-payment-service" with a new commitment
    Then Alice's client status is changed to "active"
    And the failed recovery attempt counter is reset to 0
    And the recovery lockout is cleared
    And new recovery words are generated and returned to the administrator
    And a new Argon2id hash is stored for the new recovery words

  # --- Error Cases ---

  Scenario: Reactivation without admin credentials is refused
    When an unauthenticated caller attempts to reactivate client "alice-payment-service"
    Then the reactivation is refused
    And the reason indicates that administrator authentication is required
    And the attempt is recorded in the audit log as an unauthorized reactivation attempt

  Scenario: Reactivation of non-suspended client is refused
    Given Alice's client status is "active"
    When administrator Bob attempts to reactivate client "alice-payment-service"
    Then the reactivation is refused
    And the reason indicates the client is not in a suspended state
    And the attempt is recorded in the audit log

  Scenario: Reactivation requires new commitment — old secret compromised
    When administrator Bob calls the reactivation endpoint without providing a new commitment
    Then the reactivation is refused
    And the reason indicates that a new commitment is required
    And the old commitment is never reused after a suspension
```

## Feature: Recovery Configuration

```gherkin
Feature: Recovery Configuration
  As an operator
  I want to configure the recovery mechanisms available to my clients
  So that I can balance security requirements with usability for my specific deployment

  Background:
    Given the authentication service is operational

  # --- Happy Path ---

  Scenario: Operator configures recovery mode
    When operator "acme-corp" configures recovery mode as "phrase_only"
    Then clients enrolled under "acme-corp" can only recover via BIP-39 phrase
    And the external intervention endpoint is disabled for "acme-corp" clients
    When operator "enterprise" configures recovery mode as "external_only"
    Then clients enrolled under "enterprise" can only recover via external intervention
    And the recovery phrase endpoint is disabled for "enterprise" clients
    When operator "standard" configures recovery mode as "phrase_and_external"
    Then clients enrolled under "standard" can use either recovery method

  Scenario: Default mode is phrase_and_external
    Given a new operator has not explicitly configured a recovery mode
    When a client enrolls under this operator
    Then the effective recovery mode is "phrase_and_external"
    And the enrollment response includes recovery words
    And the external intervention endpoint is available

  Scenario: Word count configurable with entropy levels
    When operator "standard" configures word count as 12
    Then enrollments produce 12 words encoding 128 bits of entropy
    When operator "enhanced" configures word count as 18
    Then enrollments produce 18 words encoding 192 bits of entropy
    When operator "maximum" configures word count as 24
    Then enrollments produce 24 words encoding 256 bits of entropy

  # --- Edge Cases ---

  Scenario: Argon2id parameters configurable per operator
    When operator "resource-constrained" configures Argon2id with memory 32 MB, iterations 2, parallelism 2
    And operator "high-security" configures Argon2id with memory 128 MB, iterations 5, parallelism 8
    Then each operator's clients use their respective Argon2id parameters
    And the parameters are stored alongside the recovery key hash for verification

  Scenario: Configuration change does not affect existing clients
    Given operator "acme-corp" has clients enrolled with 12-word recovery phrases and Argon2id memory 64 MB
    When operator "acme-corp" changes configuration to 24-word phrases and Argon2id memory 128 MB
    Then existing clients retain their 12-word recovery capability with 64 MB Argon2id
    And only newly enrolled clients use the 24-word configuration with 128 MB Argon2id
    And existing clients' recovery key hashes remain valid and verifiable
```

## Feature: Edge Cases & Security

```gherkin
Feature: Edge Cases & Security
  As the authentication system
  I want recovery mechanisms to be hardened against attack vectors
  So that recovery cannot be exploited to bypass the security of the protocol

  Background:
    Given the authentication service is operational

  # --- Edge Cases ---

  Scenario: Recovery phrase brute-force is computationally infeasible
    Given a 12-word recovery phrase from the BIP-39 wordlist of 2048 words
    Then the search space is 2048^12 = 2^132 combinations
    And at 1 billion attempts per second this would take approximately 1.7 * 10^31 years
    And the Argon2id cost per attempt (64 MB, 3 iterations) further reduces attacker throughput
    And the 3-attempt lockout makes online brute-force impossible

  Scenario: Timing-safe comparison of recovery hash
    Given the system uses Argon2id for recovery key hashing
    When comparing the derived hash against the stored hash
    Then the comparison is performed in constant time
    And Argon2id's inherent computational cost dominates the timing profile
    And no timing side-channel reveals partial hash matches

  Scenario: Recovery during concurrent suspension attempt — suspension wins
    Given Alice's client status is "active"
    And a concurrent session anomaly is detected, triggering a suspension
    And Alice simultaneously submits a recovery request
    When both operations are processed
    Then the suspension takes effect first
    And the recovery request is processed against the suspended state
    And no race condition allows bypassing the suspension

  Scenario: Recovery words cannot be retrieved after enrollment
    Given Alice enrolled and received her recovery words
    When Alice calls any API endpoint requesting her recovery words
    Then no endpoint returns the recovery words
    And the system has no mechanism to reconstruct or display the words
    And the only stored artifact is the Argon2id hash

  # --- Error Cases ---

  Scenario: Client recovered with new commitment invalidates all old artifacts
    Given Alice has been suspended and holds old tokens and old pending challenges
    When Alice successfully recovers with new commitment via phrase or external intervention
    Then the old commitment is permanently replaced
    And all tokens issued under the old commitment are invalidated
    And all challenges issued under the old commitment are invalidated
    And any proof generated with the old secret will be rejected
    And the new commitment version is incremented
```

---

## TDD Implementation Order

### Phase 1: Recovery Phrase Generation

1. **RED**: BIP-39 English wordlist loaded (2048 words)
2. **RED**: 12 random words selected from wordlist using CSPRNG
3. **RED**: Recovery key derived from words using Argon2id with salt "mnemonic" + clientIdentifier
4. **RED**: Argon2id parameters: memory 64 MB, iterations 3, parallelism 4, output 32 bytes
5. **RED**: Recovery key hash stored alongside client record
6. **RED**: Recovery words NOT stored server-side (only hash retained)
7. **RED**: Intermediate recovery key zeroized from memory after hashing
8. **RED**: Enrollment response includes recovery words exactly once

### Phase 2: Word Count Configuration

9. **RED**: Word count configurable: 12 (128 bits), 18 (192 bits), 24 (256 bits)
10. **RED**: Argon2id parameters configurable per operator
11. **RED**: Default recovery mode is "phrase_and_external"
12. **RED**: Configuration change does not affect existing clients

### Phase 3: Recovery via Phrase (Mode 3) — Core

13. **RED**: Suspended client provides correct words → Argon2id hash matches → recovery authorized
14. **RED**: Recovery requires new commitment (old secret compromised)
15. **RED**: Recovery replaces old commitment with new commitment atomically
16. **RED**: Recovery generates new enrollment receipt with same identifier
17. **RED**: New recovery words generated and displayed on successful recovery
18. **RED**: Recovery resets failed attempt counter and lockout
19. **RED**: ClientRecovered event published with method "phrase"

### Phase 4: Recovery via Phrase — Error Handling

20. **RED**: Incorrect words → recovery refused (indistinguishable response)
21. **RED**: Failed recovery attempt counter increments on incorrect words
22. **RED**: 3 failed attempts → recovery path permanently locked
23. **RED**: Locked client response indistinguishable from other failures
24. **RED**: Recovery refused for non-suspended client (indistinguishable response)
25. **RED**: Recovery refused for revoked client (indistinguishable response)
26. **RED**: Constant-time responses across all recovery refusal reasons

### Phase 5: Recovery via External Intervention (Mode 1)

27. **RED**: ClientSuspended event published with reason for external system consumption
28. **RED**: Reactivation endpoint requires admin credentials
29. **RED**: Reactivation requires new commitment (old secret compromised)
30. **RED**: Reactivation changes client status from "suspended" to "active"
31. **RED**: Reactivation resets failed attempts, lockout, and generates new recovery words
32. **RED**: ClientReactivated event published with admin identity
33. **RED**: Reactivation refused without admin credentials
34. **RED**: Reactivation refused for non-suspended client

### Phase 6: Security Hardening & Integration

35. **RED**: Timing-safe comparison of Argon2id hash (constant-time)
36. **RED**: Recovery during concurrent suspension — suspension wins
37. **RED**: Recovery words cannot be retrieved after enrollment (no endpoint exists)
38. **RED**: Recovery with new commitment invalidates all old tokens and challenges
39. **RED**: Recovery mode configuration: "phrase_only", "external_only", "phrase_and_external"
40. **RED**: End-to-end: enrollment with words → suspension → phrase recovery → new commitment → active
