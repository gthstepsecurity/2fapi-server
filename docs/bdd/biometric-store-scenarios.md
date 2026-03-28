# BDD Scenarios — Biometric Credential Store (Tier 2)

> Generated on 2026-03-26 via BDD Workshop
> Source: CEO sprint directive — WebAuthn Credential Manager adapter

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Biometric Enrollment | 2 | 10 | 3 | 4 | 3 |
| Biometric Authentication | 2 | 11 | 3 | 3 | 5 |
| Capability Detection | 2 | 8 | 2 | 3 | 3 |
| Credential Lifecycle | 2 | 10 | 2 | 4 | 4 |
| **Total** | **8** | **39** | **10** | **14** | **15** |

## Context

Tier 2 is the most convenient storage tier: the user's derived secret is stored
in the OS-level Credential Manager (via WebAuthn) and retrieved via biometric
verification (fingerprint, face). The user never types their passphrase on that device.

```
ENROLLMENT (one-time per device)
  After passphrase derivation and commitment registration:
    1. SDK checks: platform authenticator available?
    2. YES → "Enable fingerprint login?"
    3. User confirms with biometric gesture
    4. SDK creates a WebAuthn credential storing the derived secret
    5. Future logins: fingerprint → secret → proof → JWT

AUTHENTICATION (every login)
    1. SDK detects biometric credential for this email
    2. Browser prompts for biometric verification
    3. User touches fingerprint sensor / shows face
    4. SDK retrieves secret from Credential Manager
    5. SDK computes proof in WASM → sends to server
    6. Secret zeroized from memory
```

### Security Model

The Credential Manager is OS-level, not browser-level:
- More resistant to browser compromise than localStorage (Tier 1)
- Protected by hardware secure element on modern devices
- Requires user verification (biometric or device PIN) for each access
- Bound to the origin (RP ID) — no cross-origin access

### Threat model (hostile browser)

| Threat | Tier 2 mitigation |
|--------|------------------|
| Malicious extension | Cannot access Credential Manager (OS-level API) |
| JS runtime compromise | Secret passes through WASM briefly (same as other tiers) |
| Spectre on WASM | Same mitigation: minimize exposure, zeroize immediately |
| Physical device theft | Requires biometric or device PIN to unlock credential |

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User with biometric hardware (MacBook Touch ID) | Transparent login via fingerprint |
| Bob | User with biometric hardware but prefers password | Decline biometric, use Tier 1 |
| Carol | Tenant administrator | Configure whether biometrics are allowed |
| SDK | 2FApi client module | Create/retrieve WebAuthn credentials |
| Browser | WebAuthn relying party | Mediate between SDK and OS authenticator |

## Hypotheses

1. WebAuthn is used with `authenticatorAttachment: "platform"` (no roaming keys/USB)
2. The secret (s, r) is stored as the credential's `userHandle` field (64 bytes, encrypted by the platform)
3. `isUserVerifyingPlatformAuthenticatorAvailable()` determines if Tier 2 is offered
4. Only ONE tier is active per device (mutual exclusion: Tier 1 OR Tier 2, not both)
5. The recovery phrase is shown BEFORE the tier selection prompt
6. Each browser profile is a separate "device" (separate credential namespace)
7. The RP ID is the tenant's domain (e.g., "acme.com") — not the 2FApi domain
8. Credential Manager access requires user verification every time (no silent access)

---

## Biometric Enrollment

### Feature: Storing the derived secret in the Credential Manager via WebAuthn

  As a user (Alice)
  I want to store my secret with my fingerprint
  So that I can sign in without typing my passphrase on this device

  Background:
    Given Alice is enrolled with passphrase "blue tiger fast moon"
    And the SDK just derived her secret and registered the commitment
    And Alice's device supports a platform authenticator (Touch ID)

  # --- Happy Path ---

  Scenario: Alice enables biometric login during enrollment
    Given the enrollment wizard shows "How do you want to protect this device?"
    And the options are:
      | Option | Available |
      | Biometrics (fingerprint/face) | Yes |
      | Device password | Yes |
      | No protection (shared device) | Yes |
    When Alice selects "Biometrics"
    Then the browser prompts "2FApi wants to create a passkey for alice@acme.com"
    And Alice touches her fingerprint sensor
    And the SDK creates a WebAuthn credential with:
      | Field | Value |
      | rp.id | "acme.com" |
      | user.id | <client_id bytes> |
      | user.name | "alice@acme.com" |
      | userVerification | "required" |
      | authenticatorAttachment | "platform" |
    And the derived secret (s, r) is stored as the credential's userHandle
    And Alice sees "Fingerprint login enabled for this device"
    And the secret is zeroized from WASM memory

  Scenario: Bob declines biometric enrollment
    Given Bob's device supports biometrics
    When the enrollment wizard offers biometric protection
    And Bob selects "Device password" instead
    Then no WebAuthn credential is created
    And Bob's device is set to Tier 1 (password-locked vault)
    And Bob can enable biometrics later from settings

  Scenario: Biometric enrollment stores secret as userHandle
    Given Alice confirms biometric enrollment
    When the SDK calls navigator.credentials.create()
    Then the credential's userHandle contains the 64 bytes (secret || blinding)
    And the userHandle is encrypted by the platform authenticator
    And the userHandle is only retrievable with biometric verification
    And no copy of the secret remains in JS or WASM memory after enrollment

  # --- Edge Cases ---

  Scenario: Multiple accounts on same device use separate credentials
    Given Alice has a biometric credential for alice@acme.com
    When Bob enrolls on the same device and enables biometrics
    Then a separate WebAuthn credential is created for bob@acme.com
    And Alice's credential is untouched
    And the browser manages which credential to offer based on the RP ID and user ID

  Scenario: Re-enrollment replaces existing biometric credential
    Given Alice already has a biometric credential on this device
    When Alice re-enrolls (new passphrase, new secret)
    Then the old credential is revoked (excludeCredentials list)
    And a new credential is created with the new secret
    And the old secret is no longer retrievable

  Scenario: Admin enables biometric-only policy
    Given Carol configures the tenant policy to "biometric_required"
    When Alice enrolls on a device with biometrics
    Then the SDK skips the tier selection and directly prompts for biometric
    And Alice must enable biometrics (Tier 1 and Tier 0 not offered)

  Scenario: Admin disables biometrics for the tenant
    Given Carol configures the tenant policy to "biometric_disabled"
    When Alice enrolls on a device with biometrics
    Then the biometric option is not shown
    And Alice must choose between Tier 1 (password) or Tier 0 (shared)

  # --- Error Cases ---

  Scenario: User cancels biometric prompt
    Given Alice selected biometric enrollment
    When the browser shows the fingerprint prompt
    And Alice cancels the prompt
    Then the SDK falls back to offering Tier 1 (password) or Tier 0 (shared)
    And no credential is created
    And Alice can retry biometric enrollment from settings later

  Scenario: Platform authenticator rejects credential creation
    Given the device's Credential Manager is full or locked
    When the SDK calls navigator.credentials.create()
    And the operation fails with NotAllowedError
    Then Alice sees "Could not save biometric credential. Try device password instead."
    And Alice is offered Tier 1 as fallback

  Scenario: Biometric enrollment on a device without sensor
    Given Bob's desktop has no fingerprint reader or camera
    When the SDK calls isUserVerifyingPlatformAuthenticatorAvailable()
    And the result is false
    Then the biometric option is NOT shown in the enrollment wizard
    And Bob chooses between Tier 1 and Tier 0

---

## Biometric Authentication

### Feature: Authenticating with biometric verification via Credential Manager

  As a user (Alice) with biometrics enabled
  I want to sign in with my fingerprint
  So that I never need to type my passphrase on this device

  Background:
    Given Alice has a biometric credential stored for alice@acme.com
    And Alice navigates to the login page

  # --- Happy Path ---

  Scenario: Transparent login with fingerprint
    Given the SDK detects a biometric credential for alice@acme.com
    When Alice enters her email
    Then the browser immediately prompts for biometric verification
    And Alice touches the fingerprint sensor
    And the Credential Manager returns the userHandle (secret || blinding)
    And the SDK sends the secret to WASM for proof generation
    And the WASM module generates the proof and zeroizes the secret
    And the server verifies the proof and issues a JWT
    And Alice is logged in (total time: < 2 seconds)

  Scenario: Biometric login with face recognition
    Given Alice's device has Face ID (no fingerprint)
    When the browser prompts for biometric verification
    Then Alice looks at the camera
    And the authentication proceeds identically to fingerprint
    And the secret is retrieved, proof generated, and secret zeroized

  Scenario: Biometric credential is origin-bound
    Given Alice's credential was created for rp.id = "acme.com"
    When Alice visits https://app.acme.com/login
    Then the credential is available (same RP ID)
    And when Alice visits https://evil.com/phishing
    Then no credential is offered (different RP ID)
    And the phishing page cannot retrieve Alice's secret

  # --- Edge Cases ---

  Scenario: Biometric fails — fallback to passphrase
    Given Alice's fingerprint is not recognized (wet finger, gloves)
    When Alice cancels the biometric prompt
    Then the SDK shows the passphrase input fields (Tier 0 fallback)
    And Alice types "blue tiger fast moon"
    And authentication proceeds via Argon2id derivation
    And the biometric credential remains stored (not deleted)

  Scenario: Biometric fails — fallback to device PIN (OS-level)
    Given Alice's fingerprint is not recognized
    When Alice selects "Use device PIN" in the browser prompt
    Then the OS Credential Manager accepts the device PIN as verification
    And the secret is retrieved from the credential
    And authentication proceeds normally

  Scenario: "Use passphrase instead" link skips biometric
    Given the login page shows the biometric prompt
    When Alice clicks "Use passphrase instead" (below the prompt)
    Then the biometric prompt is dismissed
    And the 4-word passphrase input is shown
    And authentication proceeds via Tier 0 flow

  # --- Error Cases ---

  Scenario: Credential Manager returns empty userHandle
    Given a platform update corrupted the credential
    When the SDK retrieves the credential and userHandle is empty
    Then the SDK detects the corruption
    And the SDK deletes the invalid credential
    And Alice is prompted to enter her passphrase
    And after successful auth, Alice is offered to re-enroll biometrics

  Scenario: WebAuthn assertion fails with UnknownError
    Given the OS secure element encountered an internal error
    When navigator.credentials.get() rejects
    Then Alice sees "Biometric verification failed. Please try again or use passphrase."
    And Alice can retry or fall back to passphrase

  Scenario: Biometric timeout (user does not respond)
    Given the browser shows the fingerprint prompt
    When Alice does not touch the sensor for 60 seconds
    Then the browser times out the WebAuthn operation
    And the SDK shows the passphrase input as fallback
    And no error is displayed (timeout is a normal user action)

  Scenario: Extension cannot intercept Credential Manager access
    Given a malicious extension is installed
    When the SDK calls navigator.credentials.get()
    Then the extension cannot hook the Credential Manager API (OS-level)
    And the extension cannot read the userHandle (never exposed to JS content script)
    And the only JS-visible data is the assertion signature (not the secret)

  Scenario: WebAuthn relay attack mitigated by platform attachment
    Given an attacker sets up a phone-as-authenticator relay via BLE
    When the attacker's relay tries to satisfy a WebAuthn assertion
    Then the assertion requires authenticatorAttachment: "platform"
    And the relay uses a roaming authenticator (cross-platform)
    And the server rejects the assertion (wrong attachment type)
    And the relay attack fails because only the local hardware is accepted

---

## Capability Detection

### Feature: Detecting biometric capabilities before offering Tier 2

  As the 2FApi client SDK
  I want to reliably detect whether the device supports biometric authentication
  So that I only offer Tier 2 when it will work

  # --- Happy Path ---

  Scenario: Device with platform authenticator detected
    Given Alice's MacBook has Touch ID
    When the SDK calls PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    And the result is true
    Then the SDK offers Tier 2 (biometric) in the enrollment wizard
    And the option shows "Use Touch ID for faster login"

  Scenario: Device without any biometric hardware
    Given Bob's desktop has no fingerprint reader and no camera
    When the SDK checks for platform authenticator
    And the result is false
    Then Tier 2 is NOT offered in the enrollment wizard
    And Bob sees only Tier 1 (password) and Tier 0 (shared)

  # --- Edge Cases ---

  Scenario: WebAuthn API exists but no platform authenticator
    Given the browser supports WebAuthn (PublicKeyCredential is defined)
    But no platform authenticator is available (only USB security keys)
    When the SDK checks isUserVerifyingPlatformAuthenticatorAvailable()
    And the result is false
    Then Tier 2 is NOT offered
    And USB/NFC security keys are not supported (platform only)

  Scenario: Browser does not support WebAuthn at all
    Given the browser does not define PublicKeyCredential
    When the SDK checks for WebAuthn support
    Then the SDK skips the biometric check entirely
    And Tier 2 is not offered

  Scenario: Virtual machine without passthrough biometrics
    Given Alice uses a VM without biometric passthrough
    When the SDK checks for platform authenticator
    And the VM reports no authenticator available
    Then Tier 2 is NOT offered
    And Alice uses Tier 1 or Tier 0

  # --- Error Cases ---

  Scenario: Detection API throws (browser bug)
    Given isUserVerifyingPlatformAuthenticatorAvailable() throws an error
    When the SDK catches the exception
    Then the SDK conservatively assumes no biometrics
    And Tier 2 is NOT offered
    And a warning is logged

  Scenario: Detection returns true but credential creation fails
    Given the detection reports a platform authenticator
    But the authenticator rejects credential creation (policy, full storage)
    When Alice selects biometric enrollment and it fails
    Then Alice is smoothly redirected to Tier 1 (password) option
    And no confusing error is shown

  Scenario: Biometric hardware disabled in OS settings
    Given Alice's laptop has Touch ID hardware
    But Alice disabled biometrics in System Preferences
    When the SDK checks for platform authenticator
    Then the result may be true (hardware exists) but credential creation fails
    And the SDK catches the NotAllowedError and falls back to Tier 1

---

## Credential Lifecycle

### Feature: Managing biometric credentials through their lifecycle

  As the 2FApi client SDK
  I want to handle credential rotation, deletion, and revocation
  So that the biometric store stays consistent with the server-side state

  # --- Happy Path ---

  Scenario: User switches from biometric to password vault
    Given Alice has biometric login enabled (Tier 2)
    When Alice goes to settings and selects "Switch to device password"
    And Alice enters her passphrase to confirm identity
    Then the biometric credential is deleted from the Credential Manager
    And a new password-locked vault is created (Tier 1)
    And Alice now logs in with her device password

  Scenario: Biometric credential deleted when user changes passphrase
    Given Alice has biometric login enabled with secret derived from "blue tiger fast moon"
    When Alice changes her passphrase to "red ocean calm star"
    Then the old biometric credential is revoked
    And a new credential is created with the new secret
    And Alice re-confirms with her fingerprint
    And future logins use the new secret

  # --- Edge Cases ---

  Scenario: User deletes credential from OS keychain directly
    Given Alice removes the 2FApi entry from her macOS Keychain
    When Alice tries to log in
    Then navigator.credentials.get() returns no matching credential
    And the SDK falls back to passphrase input (Tier 0)
    And after successful auth, Alice is offered to re-enable biometrics

  Scenario: Brute-force wipe deletes biometric credential
    Given Alice's auth failure counter reached 5 (passphrase brute-force)
    When the server triggers a device wipe
    Then the SDK attempts to delete the biometric credential
    And if deletion succeeds, the credential is gone
    And if deletion fails (no JS API to delete), the credential persists
    But the server has revoked the commitment — the credential's secret is useless
    And Alice must re-enroll from another device

  Scenario: Admin changes policy from biometric to password-only
    Given Alice has biometric login enabled
    And Carol changes the tenant policy to "biometric_disabled"
    When Alice visits the login page
    Then the SDK detects the policy change from the server
    And the SDK does NOT prompt for biometrics
    And Alice is informed "Your organization now requires passphrase or password login"
    And Alice must authenticate via passphrase
    And Alice can then set up a password vault (Tier 1) if desired

  Scenario: Credential survives browser update
    Given Alice has a biometric credential
    When her browser auto-updates to a new version
    Then the credential persists (stored at OS level, not browser level)
    And Alice can still authenticate via fingerprint

  # --- Error Cases ---

  Scenario: Credential created on one browser profile not available on another
    Given Alice enabled biometrics on Chrome (default profile)
    When Alice opens Chrome with a different profile (work profile)
    Then no biometric credential is found
    And Alice must authenticate via passphrase
    And each browser profile has independent credentials

  Scenario: Secure element hardware failure
    Given Alice's Touch ID sensor stops working (hardware failure)
    When Alice tries to authenticate
    Then the biometric prompt fails or is not shown
    And Alice falls back to passphrase (Tier 0)
    And Alice sees "Fingerprint unavailable. Use your passphrase."

  Scenario: Stale credential with revoked server commitment
    Given Alice was revoked on the server (admin action)
    But Alice's device still has the biometric credential
    When Alice authenticates and the SDK sends the proof
    Then the server rejects (commitment revoked)
    And Alice sees "Your account has been revoked. Contact your administrator."
    And the biometric credential is deleted locally (cleanup)

  Scenario: Platform upgrade changes Credential Manager behavior
    Given Alice's OS upgraded and the Credential Manager format changed
    When Alice tries to log in
    And the credential is not retrievable (incompatible format)
    Then Alice falls back to passphrase
    And after successful auth, Alice is offered to re-create the biometric credential
