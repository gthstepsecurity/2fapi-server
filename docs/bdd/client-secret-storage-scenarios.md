# BDD Scenarios — Client Authentication & Secret Derivation

> Generated on 2026-03-25 (v3 — with password-locked vault tier)
> Source: CEO directives — passphrase or PIN as primary auth, tiered storage protection

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Credential Choice at Enrollment | 2 | 10 | 3 | 4 | 3 |
| Passphrase Authentication (4 words) | 2 | 11 | 3 | 4 | 4 |
| PIN Authentication (6 digits) | 2 | 11 | 3 | 4 | 4 |
| Password-Locked Vault (Tier 1) | 10 | 45 | 10 | 17 | 18 |
| Biometric Storage (Tier 2) | 2 | 8 | 2 | 3 | 3 |
| Brute-Force Wipe | 2 | 12 | 2 | 5 | 5 |
| Device Binding & Zeroization | 2 | 8 | 2 | 3 | 3 |
| **Total** | **20** | **105** | **25** | **40** | **40** |

> Password-Locked Vault scenarios: see [password-locked-vault-scenarios.md](./password-locked-vault-scenarios.md)

## Storage Tiers

```
┌──────────────────────────────────────────────────────┐
│               STORAGE TIER HIERARCHY                  │
│                                                       │
│  Tier 0 — Shared device                              │
│    Nothing persisted. Passphrase/PIN typed every time.│
│    Argon2id → secret → proof → zeroize.              │
│                                                       │
│  Tier 1 — Password-locked vault                      │
│    Secret encrypted with AES-256-GCM in localStorage.│
│    Key derived: password → Argon2id → HKDF → AES key.│
│    Server-side attempt counter (3 tries → wipe).     │
│    TTL: 72h default (admin-configurable).            │
│                                                       │
│  Tier 2 — Biometric store                            │
│    Secret in Credential Manager (WebAuthn).           │
│    Fingerprint/face → transparent login.             │
│    Requires platform authenticator hardware.          │
└──────────────────────────────────────────────────────┘
```

## Authentication Model

```
┌──────────────────────────────────────────────────────┐
│                     ENROLLMENT                        │
│                                                       │
│  User chooses:  [4-word passphrase]  OR  [6-digit PIN]│
│                                                       │
│  Argon2id(passphrase_or_pin, salt) → secret s         │
│  Commitment C = s·G + r·H → sent to server            │
│  Recovery phrase (12-24 words) → shown once            │
│                                                       │
│  Device protection:                                   │
│    Biometrics available? → Tier 2 (Credential Manager)│
│    No biometrics?        → Tier 1 (password vault)    │
│    Shared device?        → Tier 0 (no persistence)    │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                     EVERY LOGIN                       │
│                                                       │
│  Tier 2: Biometrics stored?                           │
│    YES → transparent login (Secure Enclave)           │
│  Tier 1: Vault in localStorage?                       │
│    YES → device password → AES-GCM decrypt → secret   │
│          (server validates attempt first)              │
│  Tier 0: No storage?                                  │
│    → type passphrase or PIN                           │
│    → Argon2id → secret → proof → zeroize              │
│                                                       │
│  All tiers: secret zeroized after proof computation   │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                  BRUTE-FORCE PROTECTION               │
│                                                       │
│  Auth attempts (passphrase/PIN): server-side counter  │
│    → 5 failures → wipe biometric + vault + revoke     │
│                                                       │
│  Vault unseal attempts: server-side counter           │
│    → 3 failures → wipe vault only                     │
│    → Passphrase fallback still available              │
│    → Cannot be reset from client (tamper-proof)       │
└──────────────────────────────────────────────────────┘
```

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User who prefers a passphrase | Authenticate with "blue tiger fast moon" |
| Bob | User who prefers a PIN | Authenticate with "847291" |
| Carol | Tenant administrator | Configure brute-force threshold and credential policy |
| Eve | Attacker | Guess Alice's passphrase or Bob's PIN |
| SDK | 2FApi client WASM | Derive secret, compute proof, zeroize memory |

## Hypotheses

1. Every user MUST choose a passphrase (4 words) or PIN (6 digits) at enrollment — no exception
2. Biometric storage is an optional comfort layer on top of the passphrase/PIN
3. Argon2id derivation takes 500ms+ (memory: 64MB, iterations: 3, parallelism: 1)
4. The salt for Argon2id is derived from (user_email + tenant_id) — deterministic so any device can derive the same secret
5. The brute-force wipe threshold is configurable by admin (default: 5 attempts)
6. The server never sees the passphrase, PIN, or derived secret — only the commitment and proofs
7. Admin can enforce "passphrase only" or "PIN only" or "user's choice" per tenant

---

## Credential Choice at Enrollment

### Feature: Choosing authentication credential during enrollment

  As a new user
  I want to choose between a 4-word passphrase or a 6-digit PIN
  So that I have a memorable way to authenticate on any device

  Background:
    Given the platform "Acme Corp" uses 2FApi authentication

  # --- Happy Path ---

  Scenario: Alice chooses a 4-word passphrase
    Given Alice is completing enrollment
    When the enrollment wizard shows "Choose your sign-in method"
    And Alice selects "Passphrase (4 words)"
    And Alice types "blue tiger fast moon"
    And Alice confirms by typing "blue tiger fast moon" again
    Then the SDK derives a secret via Argon2id from "blue tiger fast moon"
    And the SDK computes commitment C from the derived secret
    And C is sent to the server with a proof of possession
    And Alice sees her 12 recovery words
    And enrollment is complete

  Scenario: Bob chooses a 6-digit PIN
    Given Bob is completing enrollment
    When the enrollment wizard shows "Choose your sign-in method"
    And Bob selects "PIN (6 digits)"
    And Bob types "847291"
    And Bob confirms by typing "847291" again
    Then the SDK derives a secret via Argon2id from "847291"
    And the SDK computes commitment C from the derived secret
    And C is sent to the server with a proof of possession
    And Bob sees his 12 recovery words
    And enrollment is complete

  Scenario: Biometric storage offered after credential choice
    Given Alice chose her passphrase
    And the device supports WebAuthn with platform authenticator
    When enrollment completes
    Then the SDK asks "Store your identity with biometrics for faster login?"
    And if Alice accepts, the derived secret is stored in the Credential Manager
    And future logins can use fingerprint instead of typing the passphrase

  # --- Edge Cases ---

  Scenario: Admin enforces passphrase only
    Given Carol configured the tenant policy to "credential_type: passphrase_only"
    When Bob starts enrollment
    Then the PIN option is not available
    And Bob must choose a 4-word passphrase

  Scenario: Admin enforces PIN only
    Given Carol configured the tenant policy to "credential_type: pin_only"
    When Alice starts enrollment
    Then the passphrase option is not available
    And Alice must choose a 6-digit PIN

  Scenario: User can switch from PIN to passphrase later
    Given Bob enrolled with PIN "847291"
    When Bob goes to security settings and selects "Change to passphrase"
    And Bob enters his current PIN to confirm identity
    And Bob chooses passphrase "red ocean calm star"
    Then a new secret is derived from "red ocean calm star"
    And a new commitment replaces the old one on the server
    And Bob receives new recovery words

  Scenario: Confirmation mismatch is rejected
    Given Alice types passphrase "blue tiger fast moon"
    When Alice types "blue tiger fast moan" as confirmation
    Then the SDK rejects with "Passphrases do not match"
    And Alice must re-enter both fields

  # --- Error Cases ---

  Scenario: Empty credential is rejected
    Given Alice submits the enrollment form without entering a passphrase
    Then the SDK rejects with "Please choose a passphrase or PIN"

  Scenario: Argon2id derivation fails (out of memory)
    Given the device has very limited memory
    When the SDK attempts Argon2id with 64MB memory parameter
    Then the SDK retries with a lower memory parameter (32MB)
    And if still failing, shows "This device cannot perform secure key derivation"

  Scenario: Network failure after derivation but before enrollment
    Given Alice chose her passphrase and the secret was derived
    When the SDK attempts to send the commitment to the server
    And the network is down
    Then the derived secret is zeroized
    And Alice sees "Network error. Please try again."
    And Alice must re-enter her passphrase on retry (nothing was persisted)

---

## Passphrase Authentication (4 words)

### Feature: Authenticating with a 4-word passphrase

  As a user (Alice)
  I want to type my 4 words to sign in
  So that I can authenticate from any device without storing anything

  Background:
    Given Alice is enrolled with passphrase "blue tiger fast moon"

  # --- Happy Path ---

  Scenario: Successful login with passphrase
    Given Alice enters her email "alice@acme.com"
    When Alice types "blue tiger fast moon" in the passphrase fields
    And clicks "Sign in"
    Then the SDK shows "Verifying..." with a progress indicator (~500ms)
    And the SDK derives the secret via Argon2id
    And the SDK requests a challenge nonce from the server
    And the SDK computes a Sigma proof
    And the server verifies the proof against Alice's commitment
    And Alice is logged in and receives a JWT
    And the derived secret is zeroized from WASM memory

  Scenario: Word autocomplete speeds up entry
    Given Alice starts typing "ti" in the second field
    Then the SDK suggests BIP-39 words: "ticket", "tide", "tiger", "tilt", ...
    And Alice selects "tiger"
    And the cursor advances to the third field

  Scenario: Words can be pasted from a password manager
    Given Alice stores her passphrase in a password manager
    When Alice pastes "blue tiger fast moon" into the first field
    Then the SDK splits the text into 4 words across all fields
    And authentication proceeds normally

  # --- Edge Cases ---

  Scenario: Extra spaces between words are trimmed
    Given Alice types "  blue   tiger  fast   moon  "
    Then the SDK normalizes to "blue tiger fast moon"
    And authentication succeeds

  Scenario: Case-insensitive word matching
    Given Alice types "Blue Tiger Fast Moon"
    Then the SDK normalizes to lowercase "blue tiger fast moon"
    And authentication succeeds

  Scenario: Passphrase fields are masked by default
    Given Alice is typing her passphrase
    Then each field shows dots instead of the word
    And a toggle "Show words" reveals the text temporarily

  Scenario: Browser password manager does not interfere
    Given the passphrase fields have autocomplete="off"
    Then the browser does not offer to save or autofill the passphrase
    And no "Save password?" dialog appears after login

  # --- Error Cases ---

  Scenario: Wrong passphrase
    Given Eve types "red ocean calm star" (not Alice's passphrase)
    When the SDK derives a secret and computes a proof
    Then the server rejects (proof does not match Alice's commitment)
    And Eve sees "Authentication failed"
    And the failed attempt counter increments

  Scenario: Partial passphrase submitted
    Given Alice types only 3 words
    When Alice clicks "Sign in"
    Then the SDK rejects locally with "Please enter all 4 words"
    And no server request is made

  Scenario: Non-BIP-39 word entered
    Given Alice types "blue tiger fast hello"
    When the SDK validates the words
    Then the SDK rejects "hello" is not a valid word
    And suggests similar words: "health", "heavy", "help"

  Scenario: Server unreachable after derivation
    Given Alice typed her passphrase and the secret was derived
    When the SDK cannot reach the server for a challenge
    Then the secret is zeroized
    And Alice sees "Cannot reach server. Please try again."

---

## PIN Authentication (6 digits)

### Feature: Authenticating with a 6-digit PIN

  As a user (Bob)
  I want to type my 6-digit PIN to sign in
  So that I have a quick numeric authentication option

  Background:
    Given Bob is enrolled with PIN "847291"

  # --- Happy Path ---

  Scenario: Successful login with PIN
    Given Bob enters his email "bob@acme.com"
    When Bob types "847291" in the PIN field
    And clicks "Sign in"
    Then the SDK derives the secret via Argon2id from "847291"
    And the SDK requests a challenge and computes a proof
    And the server verifies the proof
    And Bob is logged in

  Scenario: PIN field is numeric-only with auto-advance
    Given Bob focuses the PIN field
    Then the mobile keyboard shows only numbers
    And after typing 6 digits, the form auto-submits

  Scenario: PIN entry via numpad on desktop
    Given Bob uses a desktop computer
    When Bob types on the numeric keypad
    Then the PIN field accepts numpad input normally

  # --- Edge Cases ---

  Scenario: PIN with leading zeros
    Given Bob's PIN is "007842"
    When Bob types "007842"
    Then the SDK preserves leading zeros
    And authentication succeeds

  Scenario: PIN field is masked
    Given Bob is typing his PIN
    Then the field shows dots: "●●●●●●"
    And a toggle reveals the digits temporarily

  Scenario: Copy-paste of PIN works
    Given Bob pastes "847291" from clipboard
    Then the PIN field accepts the paste
    And authentication proceeds

  Scenario: PIN entry on mobile with biometric prompt
    Given Bob's phone supports biometrics
    And Bob previously stored his secret via biometrics
    When Bob taps the PIN field
    Then the phone offers "Use fingerprint instead?"
    And Bob can choose fingerprint or continue with PIN

  # --- Error Cases ---

  Scenario: Wrong PIN
    Given Eve types "000000"
    When the SDK derives a secret from "000000"
    Then the proof does not match Bob's commitment
    And Eve sees "Authentication failed"
    And the failed attempt counter increments

  Scenario: Non-numeric input rejected
    Given someone types "abc123"
    Then the PIN field rejects non-numeric characters
    And only "123" appears in the field

  Scenario: PIN too short
    Given Bob types only "8472"
    When Bob tries to submit
    Then the SDK rejects with "PIN must be 6 digits"

  Scenario: Sequential PIN warned at enrollment
    Given Bob tries to enroll with PIN "123456"
    Then the SDK warns "This PIN is easy to guess. Choose a more random PIN."
    And Bob can proceed (warning, not blocking) or choose a different PIN

---

## Biometric Storage (optional comfort)

### Feature: Storing derived secret in Credential Manager for biometric login

  As a user (Alice)
  I want to optionally store my secret with biometrics
  So that I can skip typing my passphrase on my personal device

  Background:
    Given Alice is enrolled with passphrase "blue tiger fast moon"
    And her device supports WebAuthn with a platform authenticator

  # --- Happy Path ---

  Scenario: Alice enables biometric login
    Given Alice sees "Enable fingerprint login?"
    When Alice taps "Yes"
    And Alice confirms with her fingerprint
    Then the SDK stores the derived secret in the Credential Manager
    And future logins on this device use fingerprint only

  Scenario: Transparent login with biometrics
    Given Alice stored her secret in the Credential Manager
    When Alice navigates to the login page and enters her email
    Then the browser prompts for fingerprint
    And Alice touches the sensor
    And the SDK retrieves the secret from the Credential Manager
    And computes the proof and authenticates
    And Alice is logged in without typing anything

  # --- Edge Cases ---

  Scenario: Biometrics fail — fallback to passphrase
    Given Alice's fingerprint is not recognized
    When Alice cancels the biometric prompt
    Then the SDK shows the passphrase input fields
    And Alice types "blue tiger fast moon"
    And authentication proceeds via passphrase

  Scenario: Biometric store is per-device
    Given Alice enabled biometrics on her MacBook
    When Alice logs in from her phone
    Then the phone does not have biometric data for Alice
    And Alice must type her passphrase (or enable biometrics on the phone too)

  Scenario: Biometric store deleted by user
    Given Alice removes the 2FApi credential from her OS keychain
    When Alice tries to log in
    Then the biometric prompt fails
    And Alice falls back to her passphrase
    And can re-enable biometrics after logging in

  # --- Error Cases ---

  Scenario: Device without biometrics cannot enable this feature
    Given Bob's desktop has no fingerprint reader or camera
    When enrollment completes
    Then the "Enable biometric login" option is not shown
    And Bob always uses his PIN

  Scenario: Biometrics disabled at OS level
    Given Alice enabled biometrics previously
    And Alice later disabled biometrics in OS settings
    When Alice tries to log in
    Then the Credential Manager requires the device PIN/password instead
    And Alice enters her device unlock code
    And authentication proceeds

  Scenario: Wipe clears biometric store too
    Given Alice's brute-force counter reached the threshold on this device
    When the SDK triggers a wipe
    Then the Credential Manager entry for 2FApi is deleted
    And the passphrase cannot unlock this device anymore (commitment revoked)
    And Alice must re-enroll from another device

---

## Brute-Force Wipe

### Feature: Wiping secrets after too many failed attempts

  As the 2FApi client SDK
  I want to destroy local secrets and revoke the device commitment after too many failures
  So that brute-force attacks gain nothing

  Background:
    Given the brute-force threshold is configured to 5 attempts

  # --- Happy Path ---

  Scenario: Progressive warnings before wipe
    Given Alice has failed authentication 3 times
    When Alice fails a 4th time
    Then Alice sees "Incorrect. WARNING: 1 attempt remaining before this device is locked."

  Scenario: Wipe triggered after threshold
    Given Bob has failed authentication 5 times on this device
    When the 5th attempt fails
    Then the SDK deletes the biometric store entry (if any)
    And the SDK sends a device revocation to the server
    And the server marks this device's commitment as "revoked"
    And Bob sees "This device has been locked for security. Use your recovery phrase or another device to sign in."
    And Bob's other devices receive a notification

  # --- Edge Cases ---

  Scenario: Admin configures threshold to 3
    Given Carol set the brute-force threshold to 3 for "Acme Corp"
    When someone fails 3 times on Bob's account
    Then the wipe triggers after the 3rd attempt (not the 5th)

  Scenario: Admin configures threshold to 10
    Given Carol set the brute-force threshold to 10
    When someone fails 9 times
    Then no wipe occurs yet
    And the warning shows at attempt 9: "1 attempt remaining"

  Scenario: Counter resets after successful authentication
    Given Alice failed 4 times (1 away from wipe)
    When Alice enters the correct passphrase on the 5th attempt
    Then authentication succeeds
    And the failure counter resets to 0

  Scenario: Wipe succeeds even if server is unreachable
    Given the threshold is reached
    And the server is unreachable
    When the SDK triggers wipe
    Then the biometric store is deleted locally regardless
    And the SDK queues a pending revocation
    And the next time any page loads, the pending revocation is sent to the server
    And the user cannot authenticate from this device in the meantime

  Scenario: Counter is per-device, not global
    Given Alice fails 4 times on her MacBook
    And Alice has 0 failures on her iPhone
    When someone fails a 5th time on the MacBook
    Then the MacBook is wiped
    And the iPhone is unaffected (counter still 0)

  # --- Error Cases ---

  Scenario: Attacker triggers wipe intentionally to lock out user
    Given Eve has access to Bob's device
    When Eve enters 5 wrong PINs to trigger a wipe
    Then Bob's device is locked
    But Bob's other devices are NOT affected
    And Bob can re-enroll this device using his recovery phrase or device linking
    And the wipe event is logged on the server for admin review

  Scenario: Multiple wipes across devices triggers admin alert
    Given 3 of Alice's devices have been wiped in the last hour
    Then the server flags Alice's account for security review
    And Carol (tenant admin) receives an alert
    And Alice's remaining devices are NOT automatically wiped

  Scenario: Wipe during active session
    Given Alice is currently logged in (valid JWT)
    And someone triggers a wipe from the login page in another tab
    Then Alice's active session continues until JWT expiry
    But Alice cannot re-authenticate from this device after the session expires

  Scenario: Threshold of 0 means no wipe (disabled)
    Given Carol set the brute-force threshold to 0
    When someone fails authentication 100 times
    Then no wipe occurs
    And only the server-side rate limiting applies

  Scenario: Minimum threshold is 3
    Given Carol tries to set the brute-force threshold to 1
    Then the configuration is rejected with "Minimum threshold is 3 to prevent accidental lockout"

---

## Device Binding & Zeroization

### Feature: Ensuring secrets never persist after use

  As the 2FApi client SDK
  I want to guarantee that derived secrets are zeroized from memory after proof computation
  So that memory dump attacks have minimal exposure window

  # --- Happy Path ---

  Scenario: Secret zeroized after proof generation
    Given Alice typed her passphrase and the SDK derived the secret
    When the proof is computed and sent to the server
    Then the derived secret is overwritten with zeros in WASM linear memory
    And the JavaScript Uint8Array reference is zeroed and dereferenced
    And only the proof (public data) was sent over the network

  Scenario: Blinding factor also zeroized
    Given the Argon2id derivation produced both secret s and blinding r
    When the proof is generated
    Then both s and r are zeroized
    And only the commitment C (public) remains in server storage

  # --- Edge Cases ---

  Scenario: Error during proof computation still triggers zeroization
    Given the SDK derived the secret
    And an error occurs during multiscalar multiplication
    When the SDK catches the error
    Then the secret is zeroized BEFORE the error is propagated
    And the user sees a generic error without secret material

  Scenario: Page navigation during computation triggers zeroization
    Given the SDK is mid-computation
    When the user navigates away
    Then the beforeunload handler zeroizes the secret
    And WASM memory is released by the browser

  Scenario: Browser tab crash does not leak secret in crash report
    Given the SDK is computing a proof
    When the browser crashes
    Then the crash report does not contain the secret in stack traces
    And the WASM linear memory is not included in mini-dumps (browser policy)

  # --- Error Cases ---

  Scenario: Argon2id output is never logged
    Given the SDK derives a secret
    Then no console.log, console.debug, or telemetry call contains the derived bytes
    And no error handler includes the secret in error context

  Scenario: SharedArrayBuffer not used for secrets
    Given multiple tabs are open on the same origin
    When the SDK derives a secret in one tab
    Then the secret is in a standard ArrayBuffer (not SharedArrayBuffer)
    And other tabs cannot observe the derivation

  Scenario: Garbage collector cannot recover zeroized secret
    Given the SDK zeroized the Uint8Array containing the secret
    When the garbage collector runs
    Then the freed memory contains zeros (not the original secret)
    And no finalizer or WeakRef leaks the original bytes
