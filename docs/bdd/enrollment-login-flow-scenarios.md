# BDD Scenarios — Enrollment & Login Orchestration Flows

> Generated on 2026-03-26 via BDD Workshop
> Source: CEO sprint directive — use cases orchestrating all 3 storage tiers

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Enrollment Wizard | 2 | 12 | 3 | 5 | 4 |
| Login Tier Cascade | 2 | 15 | 4 | 6 | 5 |
| Tier Transitions | 2 | 10 | 2 | 4 | 4 |
| Cross-Tier Zeroization | 2 | 8 | 2 | 3 | 3 |
| **Total** | **8** | **45** | **11** | **18** | **16** |

## Context

The enrollment and login flows are the orchestration layer that combines:
- Tier 0 (shared device): passphrase/PIN → Argon2id → proof → zeroize
- Tier 1 (password vault): device password → server pepper → AES-GCM decrypt → proof
- Tier 2 (biometric): fingerprint/face → Credential Manager → proof

The orchestrator is responsible for:
1. Guiding the user through enrollment (5 steps)
2. Detecting the available/active tier at login
3. Cascading through fallbacks when a tier fails
4. Ensuring secret material is zeroized at every step

### Enrollment Wizard Steps

```
Step 1: Email / identity
Step 2: Credential choice (passphrase 4 words OR PIN 6 digits)
Step 3: Credential confirmation (type again)
Step 4: Recovery phrase shown (12 words, save once)
Step 5: Device protection choice:
          Biometric (if available) → Tier 2
          Device password            → Tier 1
          No protection (shared)     → Tier 0
```

### Login Tier Detection

```
1. Check: biometric credential exists for this email?
     YES → prompt biometric (Tier 2)
     fail/cancel → fall through

2. Check: encrypted vault exists in localStorage?
     YES → prompt device password (Tier 1)
     fail/cancel → fall through

3. Default: prompt passphrase/PIN (Tier 0)
     always available as ultimate fallback
```

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | New user enrolling for the first time | Complete enrollment and choose protection |
| Bob | Returning user on a known device | Log in using the most convenient tier |
| Charlie | User on a shared kiosk | Log in ephemerally, leave no trace |
| Carol | Tenant administrator | Configure allowed tiers and policies |
| SDK | 2FApi client orchestrator | Guide through enrollment/login, manage tiers |

## Hypotheses

1. The enrollment wizard is linear (no back/skip) but cancellable
2. Recovery phrase is shown BEFORE device protection choice
3. Only one tier is active per device per account (mutual exclusion)
4. The login page auto-detects the active tier and offers the appropriate UX
5. "Use passphrase instead" is ALWAYS available regardless of active tier
6. A successful passphrase login resets vault attempt counters (cross-tier benefit)
7. Enrollment requires network connectivity at all times (commitment registration)
8. Login with Tier 0 (passphrase) works even if the server is briefly unreachable during Argon2id (proof requires server for challenge)

---

## Enrollment Wizard

### Feature: Guiding a new user through enrollment with tier selection

  As a new user (Alice)
  I want to be guided through enrollment step by step
  So that I have a credential, recovery phrase, and device protection when done

  Background:
    Given Alice is a new user on the "Acme Corp" platform
    And Alice navigates to the enrollment page

  # --- Happy Path ---

  Scenario: Complete enrollment with passphrase and biometric (Tier 2)
    Given Alice enters her email "alice@acme.com"
    When the wizard advances to Step 2 (credential choice)
    And Alice selects "Passphrase (4 words)"
    And Alice types "blue tiger fast moon"
    And Alice confirms "blue tiger fast moon"
    Then the SDK derives the secret via Argon2id in WASM (~1 second)
    And the SDK computes commitment C
    And the SDK generates a proof-of-possession (Sigma proof that client knows s, r opening C)
    And the SDK sends C + proof-of-possession to the server
    And the server verifies the proof before accepting C
    And the wizard shows Step 4: "Save your 12 recovery words"
    And Alice writes down her recovery words
    And Alice confirms she saved them
    And the wizard shows Step 5: "How do you want to protect this device?"
    And Alice selects "Biometrics"
    And Alice touches her fingerprint sensor
    And enrollment is complete
    And the derived secret is zeroized from WASM memory
    And Alice sees "You're all set! Use your fingerprint to sign in."

  Scenario: Complete enrollment with PIN and password vault (Tier 1)
    Given Bob enters his email "bob@acme.com"
    When Bob selects "PIN (6 digits)" and types "847291"
    And Bob confirms "847291"
    Then the SDK derives the secret via Argon2id
    And commitment is registered on the server
    And Bob saves his recovery words
    And Bob selects "Device password" at Step 5
    And Bob types password "MyD3v!ceP@ss" and confirms
    Then the SDK requests a pepper from the server
    And the vault is sealed and stored in localStorage
    And enrollment is complete

  Scenario: Complete enrollment on shared device (Tier 0)
    Given Charlie enters his email at a shared kiosk
    When Charlie selects "Passphrase" and completes Steps 2-4
    And the wizard shows Step 5
    And Charlie selects "No protection (shared device)"
    Then no secret is persisted anywhere on the device
    And the derived secret is zeroized
    And Charlie sees "Use your 4 words to sign in from any device."

  # --- Edge Cases ---

  Scenario: Enrollment resumes after page refresh at Step 3
    Given Alice completed Step 2 (typed passphrase)
    When Alice accidentally refreshes the page
    Then the enrollment state is lost (nothing was persisted)
    And Alice must restart from Step 1
    And no partial secret or commitment exists on server

  Scenario: Admin restricts credential type to passphrase only
    Given Carol configured "credential_type: passphrase_only"
    When Bob starts enrollment
    Then Step 2 shows only the passphrase option (no PIN)
    And Bob must choose a 4-word passphrase

  Scenario: Admin restricts tiers to Tier 0 only (shared devices)
    Given Carol configured "allowed_tiers: [0]"
    When Alice reaches Step 5
    Then no choice is offered — Tier 0 is automatic
    And Alice sees "Your organization requires passphrase login every time"
    And the wizard skips Step 5

  Scenario: Biometric enrollment fails — fallback to Tier 1
    Given Alice selected biometrics at Step 5
    When the fingerprint prompt fails (NotAllowedError)
    Then Alice sees "Fingerprint setup failed. Would you like to use a device password instead?"
    And Alice selects "Yes"
    And enrollment proceeds with Tier 1

  Scenario: Recovery phrase must be confirmed before device protection
    Given Alice is at Step 4 (recovery phrase shown)
    When Alice clicks "Continue" without confirming she saved the words
    Then the wizard shows "Please confirm you saved your recovery words"
    And Alice must check "I have written down my recovery words"
    And only then can Alice proceed to Step 5

  # --- Error Cases ---

  Scenario: Network failure during commitment registration
    Given Alice typed her passphrase and the secret was derived
    When the SDK tries to register the commitment on the server
    And the network is down
    Then the derived secret is zeroized from WASM memory
    And Alice sees "Network error. Please try again."
    And Alice must re-enter her passphrase on retry (nothing was saved)

  Scenario: Server rejects commitment (duplicate client)
    Given Alice was already enrolled on another device
    When the SDK sends the commitment for alice@acme.com
    And the server rejects with "client already enrolled"
    Then Alice sees "This email is already registered. Please sign in instead."
    And the enrollment is aborted

  Scenario: WASM fails to load during enrollment
    Given Alice is on a browser without WASM support
    When Alice types her passphrase and submits
    Then the SDK shows "This browser cannot perform secure enrollment."
    And the enrollment form is disabled
    And Alice is advised to use a modern browser

  Scenario: Empty passphrase submitted
    Given Alice clicks "Continue" without typing any words
    Then the SDK rejects with "Please choose a passphrase or PIN"
    And the wizard stays on Step 2

---

## Login Tier Cascade

### Feature: Automatically detecting and offering the most convenient login tier

  As a returning user (Bob)
  I want the login page to automatically detect my device's tier
  So that I get the fastest authentication experience

  Background:
    Given Bob is enrolled with passphrase "blue tiger fast moon"
    And Bob navigates to the login page

  # --- Happy Path ---

  Scenario: Login via Tier 2 (biometric) — fastest path
    Given Bob enabled biometrics on this device
    When Bob enters his email "bob@acme.com"
    Then the SDK detects a biometric credential for bob@acme.com
    And the browser prompts for fingerprint
    And Bob touches the sensor
    And the secret is retrieved from Credential Manager
    And the SDK computes the proof in WASM and sends to server
    And Bob receives a JWT
    And the secret is zeroized
    And the JWT includes claim auth_tier: 2 (biometric)
    And total login time is under 2 seconds

  Scenario: Login via Tier 1 (password vault) — no biometric
    Given Bob's device has a password-locked vault (no biometrics)
    When Bob enters his email "bob@acme.com"
    Then the SDK detects a vault in localStorage for bob@acme.com
    And the SDK shows a password input field
    And Bob types "MyD3v!ceP@ss"
    And the SDK requests the pepper from the server
    And the SDK decrypts the vault, computes the proof, and authenticates
    And Bob is logged in
    And the JWT includes claim auth_tier: 1 (password vault)
    And the secret and OPRF output are zeroized

  Scenario: Login via Tier 0 (passphrase) — shared device
    Given Charlie is on a shared kiosk (no vault, no biometrics)
    When Charlie enters his email "charlie@acme.com"
    Then the SDK detects no credential and no vault
    And the SDK shows the 4-word passphrase input
    And Charlie types "red ocean calm star"
    And the SDK derives the secret via Argon2id in WASM (~1 second)
    And the SDK computes the proof and authenticates
    And Charlie is logged in
    And the JWT includes claim auth_tier: 0 (passphrase)
    And the secret is zeroized and nothing is persisted

  Scenario: Login auto-detects tier without user choosing
    Given Alice has biometric on Device A, vault on Device B, nothing on Device C
    When Alice enters her email on each device
    Then Device A shows fingerprint prompt immediately
    And Device B shows device password input
    And Device C shows passphrase input
    And Alice never has to manually select which tier to use

  # --- Edge Cases ---

  Scenario: Biometric fails — cascade to passphrase (skip vault)
    Given Alice has biometrics enabled (Tier 2)
    When Alice cancels the fingerprint prompt
    Then the SDK shows "Use passphrase instead" (direct to Tier 0)
    And the SDK does NOT offer Tier 1 (vault not configured on this device)
    And Alice types her passphrase and authenticates

  Scenario: Vault unseal fails — cascade to passphrase
    Given Bob has a password-locked vault (Tier 1)
    When Bob enters the wrong device password 3 times
    And the server wipes the vault
    Then the SDK deletes the local vault
    And the SDK shows "Vault locked. Enter your passphrase to sign in."
    And Bob types his passphrase and authenticates via Tier 0
    And after successful auth, Bob is offered to re-create a vault

  Scenario: "Use passphrase instead" always available
    Given any tier is active on this device
    When the login page is shown
    Then a link "Use passphrase instead" is visible
    And clicking it always shows the 4-word passphrase input
    And Tier 0 authentication is always possible

  Scenario: Successful Tier 0 login resets Tier 1 vault counter
    Given Bob's vault has 2 failed unseal attempts
    When Bob chooses "Use passphrase instead" and authenticates successfully
    Then the server resets the vault attempt counter for this device to 0
    And Bob can try his vault password again (3 attempts available)

  Scenario: Server enforces minimum tier for sensitive operations
    Given Alice authenticated via Tier 0 (passphrase)
    And the JWT has auth_tier: 0
    When Alice tries to access a sensitive API endpoint requiring tier >= 1
    Then the server rejects with "Insufficient authentication level"
    And Alice is prompted to re-authenticate with Tier 1 or Tier 2
    And after upgrading, a new JWT with the higher auth_tier is issued

  Scenario: Login preserves email across tier fallbacks
    Given Alice enters "alice@acme.com" and the biometric prompt appears
    When Alice cancels biometrics and falls back to passphrase
    Then the email field still shows "alice@acme.com"
    And Alice does not need to re-enter her email

  # --- Error Cases ---

  Scenario: No tiers available (first visit, not enrolled)
    Given Dave has never enrolled
    When Dave enters "dave@acme.com"
    Then the SDK checks: no biometric, no vault, no enrollment found
    And the SDK shows "No account found for this email. Please enroll first."
    And a link to the enrollment page is provided

  Scenario: Server unreachable — Tier 0 partially works
    Given Charlie is on a shared device
    And the server is unreachable
    When Charlie types his passphrase
    Then Argon2id derivation runs locally in WASM (no server needed)
    But the SDK cannot request a challenge nonce from the server
    And Charlie sees "Cannot reach server. Please check your connection."
    And the derived secret is zeroized

  Scenario: Server unreachable — Tier 1 does not work
    Given Bob has a password-locked vault
    And the server is unreachable
    When Bob enters his device password
    Then the SDK cannot fetch the pepper (server required)
    And Bob sees "Server verification required to unlock vault"
    And Bob is offered Tier 0 fallback (passphrase, but also needs server for challenge)

  Scenario: Both biometric and vault exist (should not happen)
    Given a bug caused both Tier 1 and Tier 2 to be set up on the same device
    When Alice enters her email
    Then the SDK prefers Tier 2 (biometric) over Tier 1 (vault)
    And the vault is silently cleaned up after successful authentication
    And only one tier remains active

  Scenario: Concurrent login attempts from same device
    Given Bob submits his passphrase in two browser tabs
    When both tabs request challenges simultaneously
    Then each tab receives a different challenge nonce
    And each tab computes an independent proof
    And the server accepts the first valid proof and issues a JWT
    And the second proof may also succeed (separate session)

---

## Tier Transitions

### Feature: Switching between storage tiers after enrollment

  As a user (Alice)
  I want to change my device protection tier
  So that I can upgrade to biometrics or downgrade to passphrase

  Background:
    Given Alice is authenticated

  # --- Happy Path ---

  Scenario: Upgrade from Tier 1 (vault) to Tier 2 (biometric)
    Given Alice has a password-locked vault on this device
    When Alice goes to security settings
    And selects "Enable biometric login"
    And Alice confirms with her fingerprint
    Then the SDK retrieves the secret from the vault (unseal)
    And creates a biometric credential with the secret
    And deletes the password-locked vault from localStorage
    And notifies the server to delete the vault pepper
    And Alice now logs in via fingerprint

  Scenario: Downgrade from Tier 2 (biometric) to Tier 0 (passphrase only)
    Given Alice has biometric login enabled
    When Alice selects "Remove biometric login"
    And Alice enters her passphrase to confirm identity
    Then the biometric credential is deleted from Credential Manager
    And no vault is created (Alice chose not to)
    And Alice must type her passphrase at every login

  # --- Edge Cases ---

  Scenario: Tier transition requires passphrase confirmation
    Given Alice wants to switch tiers
    When Alice initiates the change
    Then the SDK always asks for the passphrase (regardless of current tier)
    And the passphrase is used to derive the secret
    And the secret is used to set up the new tier
    And this ensures Alice truly owns the account

  Scenario: Tier transition on one device does not affect other devices
    Given Alice has Tier 2 on her laptop and Tier 1 on her tablet
    When Alice switches her laptop from Tier 2 to Tier 0
    Then her tablet's Tier 1 vault is unaffected
    And each device manages its tier independently

  Scenario: Admin changes allowed tiers — user forced to transition
    Given Alice has Tier 2 (biometric) enabled
    And Carol changes the policy to "allowed_tiers: [0]"
    When Alice visits the login page
    Then the SDK detects the policy change
    And the biometric prompt is not shown
    And Alice is informed "Your organization requires passphrase login"
    And Alice authenticates via passphrase
    And the biometric credential is cleaned up

  Scenario: Transition during active session
    Given Alice is authenticated (valid JWT)
    When Alice switches from Tier 2 to Tier 1 in settings
    Then the transition happens in the background
    And Alice's session is not interrupted
    And the new tier takes effect at the next login

  # --- Error Cases ---

  Scenario: Upgrade to Tier 2 fails (biometric error)
    Given Alice is trying to upgrade from Tier 1 to Tier 2
    When the biometric credential creation fails
    Then Alice's Tier 1 vault remains intact (no data loss)
    And Alice sees "Biometric setup failed. Your password vault is still active."

  Scenario: Downgrade from Tier 2 — credential deletion fails
    Given Alice is trying to remove biometric login
    When the SDK cannot delete the Credential Manager entry (browser limitation)
    Then the server-side commitment remains valid
    But the SDK marks the device as "biometric: disabled" in server metadata
    And the SDK will not prompt for biometrics on next login
    And the orphaned credential is harmless (server controls access)

  Scenario: Network failure during tier transition
    Given Alice is switching from Tier 0 to Tier 1
    When the SDK requests a pepper from the server
    And the network fails
    Then no vault is created
    And Alice sees "Network error. Tier change not applied."
    And Alice remains on Tier 0

  Scenario: Passphrase confirmation wrong during tier change
    Given Alice enters the wrong passphrase to confirm identity
    When Argon2id derives a wrong secret and the proof fails
    Then the tier change is aborted
    And Alice sees "Wrong passphrase. Tier change cancelled."
    And the current tier remains unchanged

---

## Cross-Tier Zeroization

### Feature: Ensuring secrets are zeroized at every orchestration step

  As the 2FApi security model
  I want secrets to be zeroized at every step of the orchestration flow
  So that the exposure window is minimized regardless of which tier is used

  # --- Happy Path ---

  Scenario: Enrollment zeroization checklist
    Given Alice completed enrollment (Steps 1–5)
    When enrollment is finished
    Then the following are zeroized:
      | Material | Location | When |
      | Passphrase string | JS heap | After WASM call returns |
      | Derived secret (s, r) | WASM linear memory | After commitment computed + tier setup |
      | Argon2id intermediate state | WASM linear memory | After derivation function returns |
      | Server pepper (Tier 1) | JS heap | After vault sealed |
      | Vault key (Tier 1) | JS heap | After vault encrypted |
    And only the commitment (public) was sent to the server
    And only the encrypted vault (Tier 1) or credential (Tier 2) persists

  Scenario: Login zeroization checklist (all tiers)
    Given Bob logs in via any tier
    When authentication is complete
    Then the following are zeroized:
      | Material | Location | When |
      | Secret (s, r) from vault/biometric/derivation | WASM memory | After proof generated |
      | Vault key (Tier 1) | JS heap | After decrypt |
      | Server pepper (Tier 1) | JS heap | After HKDF |
      | Passphrase string (Tier 0) | JS heap | After WASM call |
      | Proof randomness (k_s, k_r) | WASM memory | After proof computed |
    And only the JWT remains in memory for the session

  # --- Edge Cases ---

  Scenario: Fallback cascade zeroizes previous tier's material
    Given Alice tried biometric (Tier 2) and it failed
    And Alice typed her passphrase (Tier 0) as fallback
    When authentication completes
    Then the secret from the biometric credential attempt is zeroized
    And the secret from Argon2id derivation is also zeroized after proof
    And no leftover from the failed Tier 2 attempt remains

  Scenario: Error during proof — secret still zeroized
    Given the SDK retrieved the secret (any tier)
    When proof generation fails (e.g., invalid nonce)
    Then the secret is zeroized BEFORE the error is propagated
    And the error message contains no byte values
    And Alice must re-authenticate from scratch

  Scenario: Page unload during tier cascade
    Given Alice started with biometric, canceled, and is typing passphrase
    When Alice closes the browser tab
    Then the beforeunload handler zeroizes all WASM memory
    And any JS-held references are nulled
    And no secret material survives in any form

  # --- Error Cases ---

  Scenario: Zeroization function itself errors
    Given the WASM zeroize function throws (WASM instance corrupted)
    When the SDK catches the error
    Then the SDK dereferences all JS buffers (set to null)
    And navigates to the login page (clean slate)
    And logs the error to console (no secret data)
    And this is a best-effort — documented as residual risk

  Scenario: Multiple secrets in memory during tier transition
    Given Alice is upgrading from Tier 1 to Tier 2
    And the vault secret was decrypted (for biometric enrollment)
    When the biometric credential is created
    Then the vault secret is zeroized from JS/WASM
    And the vault itself is deleted from localStorage
    And the pepper is deleted from the server
    And only the biometric credential holds the secret

  Scenario: JWT leakage after session zeroization
    Given the SDK zeroized all secret material after proof
    When Eve reads the JWT from memory
    Then the JWT is a bearer token (time-limited, no secret material)
    And the JWT alone cannot derive the user's secret
    And the JWT expires per server policy (15 min shared, 24h personal)
    And this is an accepted trade-off: JWTs are session tokens, not secrets
