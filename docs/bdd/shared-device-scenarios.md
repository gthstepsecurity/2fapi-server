# BDD Scenarios — Shared Device Authentication

> Generated on 2026-03-25
> Source: CEO question — "What if multiple people use the same PC?"

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Quick Passphrase Setup | 2 | 10 | 3 | 4 | 3 |
| Shared Device Detection | 2 | 10 | 3 | 4 | 3 |
| Ephemeral Session Auth | 2 | 12 | 3 | 4 | 5 |
| Multi-User Isolation | 2 | 10 | 3 | 4 | 3 |
| Session Cleanup | 2 | 8 | 2 | 3 | 3 |
| **Total** | **10** | **50** | **14** | **19** | **17** |

## Context

The 2FApi authentication model requires a passphrase (4 BIP-39 words) or a PIN
(6 digits) at every login. The secret is derived via Argon2id and never persisted
(except optionally in the device's Credential Manager for biometric convenience).

On a shared device, the biometric store is either disabled or absent.
The user always types their passphrase or PIN. Nothing is persisted.
On a personal device, the biometric store provides transparent login.

```
Personal device:    Biometric (optional) → transparent login, passphrase as fallback
Shared device:      Passphrase or PIN typed every time → Argon2id → proof → zeroize
Both:               Nothing persisted except optional biometric store
```

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User on her personal laptop | Authenticate transparently (stored secret) |
| Bob | User on a shared kiosk PC | Authenticate by typing his 4-word passphrase |
| Carol | Tenant administrator | Configure shared device policy for her organization |
| SDK | 2FApi client SDK | Detect device type and choose the right auth flow |

## Credentials Overview

| Credential | Length | Purpose | Stored server-side? | When used |
|-----------|--------|---------|--------------------|-----------|
| Secret (s, r) | 2×32 bytes | ZKP proof computation | Never | Every auth (in memory) |
| Recovery phrase | 12-24 words | Account recovery after total loss | Never | Emergency only |
| Quick passphrase | 4 words | Derive secret on shared devices | Never (only verification hash) | Every login on shared device |

## Hypotheses

1. The quick passphrase is chosen by the user during enrollment (4 words from BIP-39 wordlist)
2. The passphrase is NOT the first 4 words of the recovery phrase (must be different)
3. Argon2id derivation from the passphrase takes 500ms+ (anti-brute-force)
4. The derivation is deterministic: same passphrase → same secret → same commitment
5. The server stores a verification hash of the derived secret (commitment C) — NOT the passphrase
6. On a shared device, nothing is written to persistent storage (no IndexedDB, no Credential Manager)
7. The "shared device" flag can be set by admin, by user choice, or by automatic detection
8. Quick passphrase is optional on personal devices but mandatory on shared devices

---

## Quick Passphrase Setup

### Feature: Choosing a quick passphrase during enrollment

  As a user (Bob)
  I want to choose a 4-word passphrase during enrollment
  So that I can authenticate from shared devices without storing my secret

  Background:
    Given Bob is completing enrollment on "Acme Corp"
    And Bob has confirmed his 12-word recovery phrase

  # --- Happy Path ---

  Scenario: Bob chooses a quick passphrase
    Given the enrollment wizard shows "Choose your quick passphrase"
    When Bob selects 4 words: "blue tiger fast moon"
    Then the SDK derives a secret via Argon2id from "blue tiger fast moon"
    And the derived secret matches the commitment already registered
    And Bob sees "Quick passphrase saved. Use these 4 words to sign in from any device."

  Scenario: Quick passphrase derivation produces the same commitment
    Given Bob's secret was generated during enrollment
    And Bob's commitment C is stored on the server
    When Bob chooses passphrase "blue tiger fast moon"
    And the SDK derives s' = Argon2id("blue tiger fast moon", salt)
    Then s' produces the same commitment C when combined with the correct blinding
    And the server can verify proofs from both the stored secret and the passphrase-derived secret

  Scenario: Bob can change his quick passphrase later
    Given Bob is authenticated
    When Bob navigates to security settings
    And Bob selects "Change quick passphrase"
    And Bob enters his current passphrase "blue tiger fast moon"
    And Bob chooses a new passphrase "red ocean calm star"
    Then a new secret is derived from "red ocean calm star"
    And a new commitment is registered on the server
    And the old commitment is replaced
    And Bob must also save new recovery words (since the secret changed)

  # --- Edge Cases ---

  Scenario: Passphrase must differ from the first 4 words of recovery phrase
    Given Bob's recovery phrase starts with "ocean brave fox table"
    When Bob tries to use "ocean brave fox table" as his quick passphrase
    Then the SDK rejects with "Your quick passphrase must be different from your recovery words"

  Scenario: Passphrase words must be from BIP-39 wordlist
    Given Bob types "hello world foo bar"
    When the SDK validates the passphrase
    Then the SDK rejects "foo" and "bar" as not in the BIP-39 wordlist
    And Bob must choose valid words

  Scenario: Passphrase must be exactly 4 words
    Given Bob types "blue tiger fast"
    When the SDK validates the passphrase
    Then the SDK rejects with "Please choose exactly 4 words"

  Scenario: Word suggestions while typing
    Given Bob starts typing "ti"
    Then the SDK suggests BIP-39 words starting with "ti": "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip"
    And Bob can select "tiger" from the suggestions

  # --- Error Cases ---

  Scenario: All four words identical is rejected
    Given Bob types "moon moon moon moon"
    When the SDK validates
    Then the SDK rejects with "Each word must be different"

  Scenario: Passphrase too common is warned
    Given Bob types "abandon abandon abandon about"
    When the SDK validates
    Then the SDK warns "This passphrase may be easy to guess. Consider choosing more unique words."
    And Bob can proceed anyway (warning, not blocking)

  Scenario: Enrollment fails if passphrase derivation does not match commitment
    Given a bug causes Argon2id to produce a different secret
    When the SDK verifies the derived secret against the commitment
    Then the SDK detects the mismatch
    And enrollment is retried with a fresh key generation

---

## Shared Device Detection

### Feature: Detecting shared device context

  As the 2FApi client SDK
  I want to detect if the current device is shared
  So that I never persist secrets on shared devices

  Background:
    Given the SDK is loaded on the login page

  # --- Happy Path ---

  Scenario: Admin configures tenant as "shared devices only"
    Given Carol set the tenant policy to "shared_devices: true"
    When the SDK loads on any device for this tenant
    Then the SDK operates in shared device mode
    And no secret is ever written to persistent storage
    And the passphrase input is always shown at login

  Scenario: User declares "this is a shared device" at first login
    Given the tenant policy is "shared_devices: ask_user"
    When Bob visits the login page for the first time on this browser
    Then the SDK asks "Is this your personal device or a shared device?"
    And Bob selects "Shared device"
    And the SDK stores only the preference flag (not the secret) in localStorage
    And all future logins on this browser show the passphrase input

  Scenario: SDK auto-detects shared device via multiple enrolled users
    Given Alice previously enrolled on this browser (secret stored)
    When Bob tries to log in on the same browser
    And the SDK detects a stored secret for a different email
    Then the SDK asks "This device has another account. Is this a shared device?"
    And if confirmed, the SDK switches to shared device mode
    And Alice's stored secret is preserved (her account, her choice)
    And Bob must use his passphrase

  # --- Edge Cases ---

  Scenario: User switches from "shared" to "personal" device
    Given Bob previously declared this device as shared
    When Bob selects "This is now my personal device" in settings
    Then the SDK offers to store Bob's secret persistently (Tier 1/2/3 cascade)
    And future logins are transparent (no passphrase needed)

  Scenario: Kiosk mode detected via browser API
    Given the browser is in kiosk mode (fullscreen, no address bar)
    When the SDK loads
    Then the SDK automatically operates in shared device mode
    And no prompt is shown (the decision is automatic)

  Scenario: Terminal server / Citrix / Remote Desktop
    Given the SDK detects a remote desktop session (via screen resolution heuristics or user agent)
    When the SDK loads
    Then the SDK suggests shared device mode
    And the user can override if it is their personal virtual desktop

  Scenario: Policy override prevents user from choosing personal mode
    Given Carol set the tenant policy to "shared_devices: enforced"
    When Bob tries to switch to personal device mode
    Then the SDK refuses with "Your organization requires shared device mode on all devices"

  # --- Error Cases ---

  Scenario: localStorage unavailable (strict privacy mode)
    Given the browser blocks localStorage
    When the SDK cannot store the device preference
    Then the SDK defaults to shared device mode (safest assumption)
    And Bob must enter his passphrase at each login

  Scenario: Admin changes policy from personal to shared
    Given Alice had her secret stored on a personal device
    And Carol changes the tenant policy to "shared_devices: enforced"
    When Alice visits the login page
    Then the SDK detects the policy change
    And the SDK deletes Alice's stored secret
    And Alice must use her passphrase from now on
    And Alice is informed "Your organization now requires passphrase login"

---

## Ephemeral Session Authentication

### Feature: Authenticating on a shared device with quick passphrase

  As a user (Bob) on a shared device
  I want to type my 4-word passphrase to authenticate
  So that nothing is left on the device after I leave

  Background:
    Given Bob is enrolled with quick passphrase "blue tiger fast moon"
    And the current device is in shared device mode

  # --- Happy Path ---

  Scenario: Successful authentication with quick passphrase
    Given Bob enters his email "bob@acme.com"
    When the login screen shows the passphrase input
    And Bob types "blue tiger fast moon"
    And clicks "Sign in"
    Then the SDK derives the secret via Argon2id (takes ~500ms)
    And the SDK requests a challenge from the server
    And the SDK computes a Sigma proof with the derived secret
    And the server verifies the proof
    And Bob receives a JWT and is logged in
    And the derived secret is zeroized from WASM memory
    And nothing is written to IndexedDB, localStorage, or Credential Manager

  Scenario: Passphrase input shows word suggestions
    Given Bob starts typing in the first passphrase field
    When Bob types "bl"
    Then the SDK suggests "black", "blade", "blame", "blanket", "blast", "bleak", "bleed", "blend", "bless", "blind", "blood", "blossom", "blue"
    And Bob selects "blue"
    And the cursor moves to the next field

  Scenario: Passphrase entry via word index numbers
    Given Bob prefers to type numbers
    When Bob toggles "Enter by number"
    And types "197 1798 682 1166"
    Then the SDK resolves to "blue tiger fast moon"
    And authentication proceeds normally

  # --- Edge Cases ---

  Scenario: Argon2id derivation takes observable time (anti-brute-force)
    Given Bob enters his passphrase
    When the SDK starts Argon2id derivation
    Then a progress indicator shows "Deriving secure key..."
    And the derivation takes between 500ms and 2000ms
    And the user cannot submit again during derivation

  Scenario: Browser tab closed during derivation
    Given Bob entered his passphrase and derivation is in progress
    When Bob closes the browser tab
    Then the WASM memory is released by the browser
    And no secret material persists anywhere

  Scenario: Multiple users authenticate sequentially on the same device
    Given Bob just logged out from the shared device
    When Alice sits down and enters her email and passphrase
    Then Alice's session is completely independent from Bob's
    And no trace of Bob's session or secret exists in memory or storage
    And Alice's authentication proceeds normally

  Scenario: Passphrase autocomplete is disabled
    Given the passphrase input fields are rendered
    Then the HTML autocomplete attribute is set to "off"
    And the fields have autocorrect disabled
    And the browser's password manager does not offer to save the passphrase

  # --- Error Cases ---

  Scenario: Wrong passphrase produces wrong secret
    Given Eve types "red ocean calm star" (not Bob's passphrase)
    When the SDK derives a secret from this passphrase
    And computes a proof
    Then the proof does not match Bob's commitment on the server
    And the server rejects with a generic "authentication failed"
    And Eve cannot distinguish "wrong passphrase" from "wrong email"

  Scenario: Passphrase brute-force is rate-limited by Argon2id cost
    Given an attacker submits passphrases at maximum speed
    Then each attempt takes at least 500ms (Argon2id)
    And the server rate-limits to 5 attempts per 10 minutes per email
    And full brute-force of 2048^4 combinations takes ~280 million years

  Scenario: Shared device mode with no quick passphrase configured
    Given Bob enrolled but skipped the quick passphrase step
    When Bob tries to log in from a shared device
    Then the SDK shows "No quick passphrase configured. Enter your full recovery phrase or use a personal device."
    And Bob can enter his 12-word recovery phrase as a fallback

  Scenario: Network disconnection during passphrase authentication
    Given Bob entered his passphrase and the SDK derived the secret
    When the SDK attempts to request a challenge from the server
    And the network is disconnected
    Then Bob sees "Network error. Please check your connection."
    And the derived secret is zeroized from memory
    And Bob must re-enter his passphrase after reconnection

  Scenario: WASM module fails to load on old shared device
    Given the shared device has a very old browser without WASM support
    When the login page loads
    Then the SDK shows "This browser cannot perform secure authentication. Please use a modern browser."
    And no fallback to server-side derivation is attempted

---

## Multi-User Isolation

### Feature: Ensuring user isolation on shared devices

  As the 2FApi client SDK
  I want to guarantee that one user's session cannot leak to another
  So that shared device usage is safe

  # --- Happy Path ---

  Scenario: No trace after logout
    Given Bob authenticated on a shared device
    When Bob clicks "Sign out"
    Then the JWT is removed from memory
    And the session cookie is cleared
    And no 2FApi data remains in IndexedDB
    And no 2FApi data remains in localStorage
    And no 2FApi data remains in sessionStorage
    And WASM memory is zeroed

  Scenario: Browser back button after logout does not reveal session
    Given Bob logged out from the shared device
    When Eve presses the browser back button
    Then the page does not display Bob's authenticated content
    And the page redirects to the login screen

  Scenario: No cross-user secret contamination in memory
    Given Bob authenticated, computed a proof, and logged out
    And the SDK zeroized all secret material
    When Alice starts her authentication
    Then no remnant of Bob's secret exists in WASM linear memory
    And Alice's Argon2id derivation uses a clean memory space

  # --- Edge Cases ---

  Scenario: Multiple tabs on shared device
    Given Bob is authenticated in tab 1
    When Alice opens a new tab on the same browser
    Then tab 2 shows the login screen (no session sharing between tabs)
    And Bob's session in tab 1 is independent

  Scenario: Session timeout on shared device is shorter
    Given the tenant policy sets shared_device_session_timeout to 15 minutes
    When Bob has been inactive for 15 minutes
    Then the session expires automatically
    And the JWT is cleared
    And the login screen is shown
    And no secret material remains

  Scenario: Forced logout on shared device when browser closes
    Given Bob is authenticated on a shared device
    When the browser is closed (or the kiosk resets)
    Then sessionStorage is cleared (browser behavior)
    And no persistent data was written (shared device mode)
    And Bob's session is effectively terminated

  # --- Error Cases ---

  Scenario: Crash recovery does not restore secret
    Given the browser crashed during Bob's session
    When the browser restarts and offers to restore tabs
    Then the restored tab shows the login screen
    And no secret material is recovered from crash data
    And no 2FApi session is restored

  Scenario: Browser extensions cannot access ephemeral session
    Given a malicious extension monitors storage events
    When Bob authenticates on a shared device
    Then no storage events are fired (nothing written to storage)
    And the extension observes no 2FApi data

  Scenario: Print/screenshot of login page does not reveal passphrase
    Given Bob is typing his passphrase
    Then the passphrase fields show dots (password masking)
    And a screenshot or print captures only masked characters

---

## Session Cleanup

### Feature: Guaranteed cleanup on shared devices

  As the 2FApi client SDK
  I want to guarantee that all traces are removed after a session ends
  So that the next user finds a clean state

  # --- Happy Path ---

  Scenario: Explicit logout cleans everything
    Given Bob is authenticated on a shared device
    When Bob clicks "Sign out"
    Then the cleanup checklist executes:
      | Target | Action |
      | WASM linear memory | Zeroize all secret-related addresses |
      | JavaScript variables | Set to null, eligible for GC |
      | sessionStorage | Clear all 2FApi keys |
      | Session cookie | Expired (Max-Age=0) |
      | JWT in memory | Set to null |
    And the login screen is displayed

  Scenario: Inactivity timeout triggers automatic cleanup
    Given Bob has been inactive for 15 minutes (shared device policy)
    When the inactivity timer fires
    Then the same cleanup checklist executes as for explicit logout
    And Bob sees "Your session has expired for security"

  # --- Edge Cases ---

  Scenario: Cleanup survives JavaScript errors
    Given the cleanup routine starts
    When an error occurs during WASM memory zeroization
    Then the cleanup continues with the remaining steps (best-effort)
    And a warning is logged to the console
    And the page navigates to the login screen regardless

  Scenario: Visibility change triggers guard
    Given Bob is authenticated on a shared device
    When the browser tab loses focus for more than 60 seconds
    Then the SDK prompts "Are you still there?" with a 30-second countdown
    And if no response, the session is cleaned up automatically

  Scenario: Page unload always triggers cleanup
    Given Bob is authenticated
    When the page is unloaded (navigation, tab close, browser close)
    Then the beforeunload handler executes the cleanup checklist
    And the sendBeacon API notifies the server to invalidate the JWT

  # --- Error Cases ---

  Scenario: Cleanup when WASM module was garbage-collected
    Given the WASM module was unloaded due to memory pressure
    When the cleanup routine attempts WASM memory zeroization
    Then the routine skips the WASM step (already freed)
    And continues with JavaScript and storage cleanup
    And the session is still terminated

  Scenario: Server-side session invalidation as fallback
    Given the shared device lost power (hard shutdown, no cleanup possible)
    When the JWT expires on the server (after the configured timeout)
    Then Bob's session is invalidated server-side
    And even if someone recovers the JWT from a memory dump, it is rejected
    And the server timeout for shared device tokens is 15 minutes (vs 24h for personal)
