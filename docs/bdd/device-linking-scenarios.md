# BDD Scenarios — 2FApi Device Linking Protocol

> Generated on 2026-03-24
> Source: CEO brainstorm — multi-device ZKP authentication without server-side secret transit

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Device Link Request | 2 | 12 | 3 | 4 | 5 |
| Device Link Verification | 2 | 14 | 3 | 5 | 6 |
| Device Link Confirmation | 2 | 10 | 2 | 4 | 4 |
| Device Management | 3 | 14 | 4 | 5 | 5 |
| Multi-Device Authentication | 2 | 10 | 3 | 4 | 3 |
| **Total** | **11** | **60** | **15** | **22** | **23** |

## Protocol Overview

```
Device A (authenticated)               Server                    Device B (new)
  │                                      │                            │
  │  Generate 4 random BIP-39 indexes    │                            │
  │  Compute chained SHA-512 hash:       │                            │
  │    h1 = SHA-512(word[i1])            │                            │
  │    h2 = SHA-512(h1 ‖ word[i2])       │                            │
  │    h3 = SHA-512(h2 ‖ word[i3])       │                            │
  │    h4 = SHA-512(h3 ‖ word[i4])       │                            │
  │                                      │                            │
  │── link-request { hash: h4 } ───────>│                            │
  │<── { link_id } ────────────────────│                            │
  │                                      │                            │
  │  Display: i1 i2 i3 i4               │   User types indexes       │
  │  (or words, toggle option)           │   on Device B              │
  │                                      │                            │
  │                                      │<── link-verify { h4' } ───│
  │                                      │    h4' == h4 ? ✓           │
  │                                      │                            │
  │<── "Authorize Device B?" ──────────│                            │
  │── link-confirm { approved } ──────>│                            │
  │                                      │── enrollment_token ──────>│
  │                                      │                            │
  │                                      │   Device B generates       │
  │                                      │   own (s_b, r_b, C_b)     │
  │                                      │                            │
  │                                      │<── enroll { C_b, proof } ─│
  │                                      │   Verify + store C_b       │
  │                                      │                            │
  │<── "Device added" ────────────────│── "Enrollment complete" ──>│
```

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User with authenticated device (Device A) | Add a new device to her account |
| Device A | Existing authenticated device | Initiate and confirm device linking |
| Device B | New device to be linked | Enroll with its own independent secret |
| Server | 2FApi backend | Verify link hash, manage enrollment tokens, store commitments |
| Eve | Attacker | Attempt to link an unauthorized device |

## Bounded Contexts

| Context | Ubiquitous Language |
|---------|-------------------------------|
| Device Link Request | link request, BIP-39 index, chained hash, link ID, TTL |
| Device Link Verification | link verification, hash match, attempt counter |
| Device Link Confirmation | authorization, approval, enrollment token |
| Device Management | device list, device name, revocation, active commitment |
| Multi-Device Authentication | commitment list, any-commitment verification, device-scoped session |

## Hypotheses

1. BIP-39 English wordlist (2048 words) is the shared dictionary between all devices
2. The chained hash uses SHA-512 (consistent with the rest of the 2FApi protocol)
3. Indexes are displayed as numbers 1-2048 by default, with a toggle to show words
4. TTL for link requests is 60 seconds, then auto-regenerate (like 2FA codes)
5. Maximum 3 verification attempts per link request before invalidation
6. Each device generates its own independent secret — no secret sharing between devices
7. Maximum 10 devices per user account (configurable by admin)
8. Device names are auto-detected from User-Agent (editable by user)

---

## Device Link Request

### Feature: Initiating a device link from an authenticated device

  As an authenticated user (Alice) on Device A
  I want to generate a device linking code
  So that I can add Device B to my account without transferring my secret

  Background:
    Given Alice is authenticated on Device A
    And Alice has an active commitment on the server

  # --- Happy Path ---

  Scenario: Alice initiates a device link request
    Given Alice selects "Add a new device" on Device A
    When Device A generates 4 random BIP-39 indexes
    And Device A computes the chained SHA-512 hash of the corresponding words
    And Device A sends the hash to the server
    Then the server creates a link request with a 60-second TTL
    And the server returns a link identifier
    And Device A displays the 4 indexes to Alice
    And a countdown timer shows the remaining time

  Scenario: Indexes are displayed as numbers by default
    Given Alice initiates a device link
    When Device A displays the linking code
    Then Alice sees 4 numbers between 1 and 2048
    And a toggle option allows switching to word display

  Scenario: Display toggles between indexes and words
    Given Alice sees the indexes "742 1891 203 1544"
    When Alice taps "Show words"
    Then Alice sees "gold tiger blind sail"
    And Alice can toggle back to indexes

  # --- Edge Cases ---

  Scenario: Link request auto-regenerates after expiry
    Given Alice initiated a link request
    And 60 seconds have elapsed
    When the countdown reaches zero
    Then Device A automatically generates 4 new indexes
    And computes a new chained hash
    And sends a new link request to the server
    And the display updates with the new indexes

  Scenario: Previous link request is invalidated on regeneration
    Given Alice initiated link request L1 with indexes "742 1891 203 1544"
    And the request expired and regenerated as L2 with indexes "501 77 1200 888"
    When someone attempts to verify using L1's indexes
    Then the verification fails because L1 no longer exists

  Scenario: Alice cancels the link request
    Given Alice is viewing the linking code
    When Alice taps "Cancel"
    Then the link request is deleted from the server
    And Device A returns to the device management screen

  # --- Error Cases ---

  Scenario: Link request fails when server is unreachable
    Given Alice selects "Add a new device"
    And the server is unreachable
    When Device A attempts to send the hash
    Then Alice sees "Unable to reach server. Check your connection."
    And no indexes are displayed

  Scenario: User is not authenticated
    Given Alice's session has expired on Device A
    When Alice selects "Add a new device"
    Then Alice is redirected to the authentication screen
    And no link request is created

---

### Feature: Chained SHA-512 hash computation

  As the 2FApi client SDK
  I want to compute a deterministic chained hash from BIP-39 indexes
  So that both devices can independently verify the same code

  Scenario: Chained hash is computed correctly
    Given the indexes are 742, 1891, 203, 1544
    And the corresponding BIP-39 words are "gold", "tiger", "blind", "sail"
    When the chained hash is computed
    Then h1 = SHA-512("gold")
    And h2 = SHA-512(h1 concatenated with "tiger")
    And h3 = SHA-512(h2 concatenated with "blind")
    And h4 = SHA-512(h3 concatenated with "sail")
    And the final hash is h4

  Scenario: Different index order produces different hash
    Given indexes "742 1891 203 1544" produce hash H1
    And indexes "1891 742 203 1544" produce hash H2
    Then H1 is not equal to H2

  Scenario: Hash computation is identical across platforms
    Given Device A runs on macOS Chrome
    And Device B runs on Android Firefox
    When both compute the chained hash for indexes "100 200 300 400"
    Then both produce the exact same hash value

---

## Device Link Verification

### Feature: Verifying the linking code on the new device

  As a user on Device B (new device)
  I want to enter the 4 indexes displayed on Device A
  So that the server can verify I have physical access to both devices

  Background:
    Given Alice initiated a link request on Device A
    And the server holds the expected hash with a 60-second TTL

  # --- Happy Path ---

  Scenario: Successful verification with correct indexes
    Given Device A displays indexes "742 1891 203 1544"
    When Alice enters "742 1891 203 1544" on Device B
    And Device B computes the chained SHA-512 hash
    And Device B sends the hash to the server
    Then the server confirms the hash matches
    And the link request status changes to "pending confirmation"
    And Device A receives a confirmation prompt

  Scenario: Verification with word input mode
    Given Device A displays words "gold tiger blind sail"
    When Alice types "gold tiger blind sail" on Device B
    And Device B looks up the indexes from the BIP-39 wordlist
    And computes the chained hash
    Then the verification succeeds identically to index input

  # --- Edge Cases ---

  Scenario: Verification attempt after TTL expiry
    Given the link request was created 65 seconds ago
    When Alice enters the correct indexes on Device B
    Then the server rejects with "Code expired, please request a new code"

  Scenario: Second attempt with correct indexes after a wrong first attempt
    Given Alice entered wrong indexes on the first attempt
    And the attempt counter is 1 of 3
    When Alice enters the correct indexes on the second attempt
    Then the verification succeeds
    And the attempt counter is not relevant anymore

  Scenario: Indexes entered in wrong order
    Given Device A displays "742 1891 203 1544"
    When Alice enters "1891 742 203 1544" on Device B
    Then the chained hash does not match
    And the server rejects the verification
    And the attempt counter increments to 1

  Scenario: Partial input (only 3 indexes)
    Given Alice enters only "742 1891 203" on Device B
    When Alice submits
    Then Device B rejects locally with "Please enter all 4 numbers"
    And no request is sent to the server

  # --- Error Cases ---

  Scenario: Maximum attempts exceeded
    Given Alice has failed verification 3 times for the same link request
    When Alice attempts a 4th verification
    Then the server rejects with "Too many attempts, request a new code"
    And the link request is permanently invalidated
    And Device A is notified that the link request was exhausted

  Scenario: Index out of valid range
    Given Alice enters "0 1891 203 2049" on Device B
    When Device B validates the input
    Then Device B rejects locally with "Each number must be between 1 and 2048"

  Scenario: Link request does not exist
    Given no link request is active for Alice's account
    When Device B sends a verification hash
    Then the server responds with "No active link request"

  Scenario: Brute force from unknown device
    Given Eve does not have access to Device A
    When Eve attempts random index combinations on Device B
    Then after 3 failed attempts the link request is invalidated
    And the probability of guessing correctly is 1 in 17.6 trillion

  Scenario: Concurrent verification from two devices
    Given Alice enters the correct indexes on Device B
    And Eve enters different indexes on Device C at the same time
    When both requests reach the server
    Then only one is processed (first to arrive)
    And the other receives "Link request already consumed"

  Scenario: Server unreachable during verification
    Given Alice enters the correct indexes on Device B
    And the server is unreachable
    Then Device B shows "Unable to verify. Check your connection."
    And Alice can retry without the attempt counting

---

## Device Link Confirmation

### Feature: Confirming device link on the authenticated device

  As an authenticated user on Device A
  I want to explicitly approve the new device
  So that no unauthorized device can be added to my account

  Background:
    Given Alice initiated a link request on Device A
    And Device B successfully verified the indexes

  # --- Happy Path ---

  Scenario: Alice approves the new device
    Given Device A shows "Authorize 'Firefox on Windows'?"
    When Alice taps "Authorize"
    Then the server generates an enrollment token for Device B
    And Device B receives the enrollment token
    And Device B generates its own secret and commitment
    And Device B sends its commitment and proof to the server
    And the server verifies the proof and stores the new commitment
    And Alice sees "New device added successfully"
    And Device B sees "Enrollment complete"

  Scenario: Alice rejects the new device
    Given Device A shows "Authorize 'Unknown device'?"
    When Alice taps "Reject"
    Then the server invalidates the link request
    And Device B receives "Link request was rejected by the account owner"
    And no enrollment token is issued
    And a security event is logged

  # --- Edge Cases ---

  Scenario: Confirmation prompt expires after 60 seconds
    Given Device A received the confirmation prompt
    When Alice does not respond within 60 seconds
    Then the link request expires automatically
    And Device B receives "Link request expired"

  Scenario: Device A goes offline before confirming
    Given Device A received the confirmation prompt
    When Device A loses network connectivity
    And 60 seconds elapse
    Then the link request expires on the server
    And Device B receives "Link request expired"

  Scenario: Device B enrollment fails after approval
    Given Alice approved the link on Device A
    And Device B received the enrollment token
    When Device B generates an invalid commitment (e.g., identity element)
    Then the server rejects the enrollment
    And the enrollment token is consumed (single-use)
    And Alice is notified "Device enrollment failed"

  # --- Error Cases ---

  Scenario: Enrollment token used twice
    Given Device B received an enrollment token
    And Device B enrolled successfully with commitment C1
    When Eve replays the same enrollment token with a different commitment
    Then the server rejects because the token was already consumed

  Scenario: Enrollment token expired
    Given Alice approved the link
    And the enrollment token has a TTL of 5 minutes
    When Device B attempts enrollment after 6 minutes
    Then the server rejects with "Enrollment token expired"

  Scenario: Confirmation from a different user session
    Given Alice is authenticated on Device A with session S1
    When someone sends a confirmation from a different session S2
    Then the server rejects because the confirmation must come from the original session

  Scenario: Concurrent approval and rejection
    Given Alice taps "Authorize" on her phone
    And Alice also taps "Reject" on her tablet (same account, different session)
    When both reach the server
    Then the first action wins (whichever arrives first)
    And the second receives "Link request already resolved"

---

## Device Management

### Feature: Listing enrolled devices

  As an authenticated user (Alice)
  I want to see all devices linked to my account
  So that I can monitor and manage my authentication devices

  Scenario: Alice views her device list
    Given Alice has 3 enrolled devices: "MacBook Pro", "iPhone 15", "Firefox on Linux"
    When Alice opens the device management screen
    Then Alice sees 3 devices with their names, enrollment dates, and last authentication time
    And Alice does NOT see commitment bytes or secrets

  Scenario: Device names are auto-detected
    Given Device B connected with User-Agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    When Device B enrolls
    Then the device is named "Chrome on Windows" automatically
    And Alice can edit the name to "Office PC"

  Scenario: Current device is highlighted
    Given Alice is viewing her device list from "MacBook Pro"
    Then "MacBook Pro" is marked as "This device"
    And it cannot be revoked from itself

---

### Feature: Revoking a device

  As an authenticated user (Alice)
  I want to revoke a lost or compromised device
  So that it can no longer authenticate as me

  Scenario: Alice revokes her lost phone
    Given Alice's "iPhone 15" has commitment C2
    When Alice selects "Revoke" on "iPhone 15" from her MacBook
    And Alice confirms the revocation
    Then commitment C2 is marked as "revoked" on the server
    And "iPhone 15" can no longer authenticate
    And Alice's other devices are unaffected
    And a security event "device_revoked" is logged

  Scenario: Revoked device attempts to authenticate
    Given "iPhone 15" was revoked
    When someone attempts to authenticate with "iPhone 15"'s secret
    Then the server rejects because C2 is revoked
    And the attempt is logged with the device identifier

  Scenario: Revoking the last device
    Given Alice has only 1 enrolled device: "MacBook Pro"
    When Alice attempts to revoke "MacBook Pro"
    Then the system warns "This is your only device. Revoking it will lock you out."
    And Alice must confirm by entering her recovery phrase
    And after revocation Alice must re-enroll to regain access

  # --- Edge Cases ---

  Scenario: Revoke all devices (panic button)
    Given Alice suspects her account is compromised
    When Alice selects "Revoke all devices"
    And Alice confirms with her recovery phrase
    Then all commitments are revoked
    And all active sessions are terminated
    And Alice must re-enroll from scratch using her recovery phrase

  Scenario: Maximum device limit reached
    Given Alice has 10 enrolled devices (the maximum)
    When Alice attempts to add an 11th device
    Then the link request is rejected with "Maximum devices reached"
    And Alice is prompted to revoke an existing device first

  # --- Error Cases ---

  Scenario: Revocation of non-existent device
    Given device "iPad Air" is not in Alice's device list
    When a request to revoke "iPad Air" is sent
    Then the server rejects with "Device not found"

  Scenario: Revocation without re-authentication
    Given Alice's session is older than 5 minutes
    When Alice attempts to revoke a device
    Then Alice must re-authenticate first (fresh proof required)
    And the revocation proceeds only after successful re-authentication

---

### Feature: Device activity monitoring

  As an authenticated user (Alice)
  I want to see recent authentication activity per device
  So that I can detect unauthorized access

  Scenario: Alice views authentication history
    Given "iPhone 15" was used to authenticate 3 times today
    When Alice views the activity for "iPhone 15"
    Then Alice sees 3 entries with timestamps, IP addresses, and locations
    And the most recent entry is highlighted

  Scenario: Suspicious activity alert
    Given "iPhone 15" last authenticated from Paris, France
    And a new authentication occurs from Tokyo, Japan 10 minutes later
    Then Alice receives a notification "Unusual activity on iPhone 15"
    And the notification suggests revoking the device if unrecognized

  Scenario: Activity log retention
    Given the platform retains 90 days of activity logs
    When Alice views activity from 91 days ago
    Then no data is available for that period
    And Alice sees "Activity logs are retained for 90 days"

---

## Multi-Device Authentication

### Feature: Authentication with any enrolled device

  As the 2FApi server
  I want to accept a valid proof from any of the user's active commitments
  So that the user can authenticate from any enrolled device

  Background:
    Given Alice has 3 active commitments: C1 (MacBook), C2 (iPhone), C3 (Linux)

  # --- Happy Path ---

  Scenario: Authentication with MacBook commitment
    Given Alice authenticates from her MacBook using secret s1
    When the server receives the proof
    Then the server checks the proof against C1 — it matches
    And Alice is authenticated
    And the session is tagged with device "MacBook"

  Scenario: Authentication with iPhone commitment
    Given Alice authenticates from her iPhone using secret s2
    When the server receives the proof
    Then the server checks the proof against C2 — it matches
    And Alice is authenticated
    And the session is tagged with device "iPhone"

  Scenario: Server tries commitments in order until one matches
    Given Alice authenticates from her Linux machine
    When the server receives the proof
    Then the server tries C1 — no match
    And the server tries C2 — no match
    And the server tries C3 — match
    And Alice is authenticated

  # --- Edge Cases ---

  Scenario: Authentication fails if no commitment matches
    Given Eve uses a secret not associated with any of Alice's commitments
    When the server receives Eve's proof
    Then the server tries C1, C2, C3 — none match
    And the authentication is rejected
    And the response is indistinguishable from a single-commitment failure

  Scenario: Performance with many devices
    Given Alice has 10 enrolled devices (10 commitments)
    When Alice authenticates
    Then the server verifies against at most 10 commitments
    And the total verification time is under 50ms
    And no timing difference reveals how many commitments were checked

  Scenario: Revoked commitment is skipped
    Given C2 (iPhone) was revoked
    When Alice authenticates from her iPhone with secret s2
    Then the server skips C2 (revoked)
    And tries C1 and C3 — neither match s2
    And the authentication fails

  # --- Error Cases ---

  Scenario: Constant-time multi-commitment verification
    Given Alice has 3 commitments and Eve has 1 commitment
    When both authenticate (one succeeds, one fails)
    Then the response time for Alice and Eve is indistinguishable
    And no timing oracle reveals the number of commitments per user

  Scenario: All commitments revoked
    Given all of Alice's commitments have been revoked
    When Alice attempts to authenticate
    Then the server rejects with a generic "authentication failed"
    And Alice must re-enroll using her recovery phrase
