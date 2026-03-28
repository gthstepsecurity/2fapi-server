# BDD Scenarios — Password-Locked Vault (Tier 1 Storage)

> Generated on 2026-03-26 (v2 — with server pepper for offline attack resistance)
> Source: CEO + founder design session — password-locked localStorage as intermediate tier

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Vault Sealing | 2 | 9 | 2 | 4 | 3 |
| Vault Unsealing | 2 | 10 | 3 | 3 | 4 |
| Server-Side Attempt Counter & Pepper | 2 | 12 | 2 | 5 | 5 |
| Vault Lifecycle & TTL | 2 | 8 | 2 | 3 | 3 |
| Offline Attack Resistance | 2 | 6 | 1 | 2 | 3 |
| **Total** | **10** | **45** | **10** | **17** | **18** |

## Context

The password-locked vault is Tier 1 in the 2FApi client storage hierarchy:

```
Tier 0 — Shared device       : nothing persisted, passphrase/PIN every login
Tier 1 — Password-locked     : localStorage encrypted by device password (this doc)
Tier 2 — Biometric store     : Credential Manager, fingerprint/face
```

Tier 1 targets devices without biometric hardware (desktop PCs, older laptops)
or users who prefer explicit password unlock over biometric convenience.

### Cryptographic Design

The vault key is derived from TWO independent secrets: the user's device password
(client-side) and a server-generated pepper (server-side). Neither alone is sufficient
to decrypt the vault. This eliminates offline brute-force attacks entirely.

```
                              SEAL (online)

password ──► Argon2id(password, salt) ──► ikm (256-bit)
                                              │
server ──► generates pepper (256-bit) ────────┤
           stored per (client_id, device_id)  │
                                              ▼
                                    HKDF-SHA256(
                                      ikm=ikm || pepper,
                                      salt=device_id,
                                      info="2fapi-vault-seal-v1"
                                    )
                                              │
                                              ▼
                                        vault_key (256-bit)
                                              │
                                              ▼
                                    AES-256-GCM encrypt(secret || blinding)
                                              │
                                              ▼
                                    localStorage["2fapi-vault"] = {
                                      iv: 12 random bytes,
                                      ciphertext: encrypted blob,
                                      tag: GCM authentication tag,
                                      device_id: "dev-<hex>",
                                      created_at: server timestamp,
                                      max_ttl_hours: 72,
                                      version: 1
                                    }


                              UNSEAL (online required)

password ──► Argon2id(password, salt) ──► ikm
                                              │
SDK: POST /v1/vault/unseal-attempt ───────────┤
  Server checks counter,                      │
  returns { pepper, attempts_remaining } ──────┤
                                              ▼
                                    HKDF-SHA256(ikm || pepper, ...)
                                              │
                                              ▼
                                    AES-256-GCM decrypt ──► (secret, blinding)
```

**Security model — two-factor vault protection:**

| Factor | Where | Purpose |
|--------|-------|---------|
| Device password | User's memory | "Something you know" |
| Server pepper | Server DB, per device | "Something the server holds" |

**Key properties:**
- Password is NEVER stored (not in localStorage, not on server, not anywhere)
- Pepper is NEVER stored on the device (only on server, per device_id)
- Without BOTH password AND pepper, the vault is indistinguishable from random noise
- AES-256-GCM authentication tag detects wrong password (decryption fails)
- Server-side counter prevents online brute-force (client cannot reset it)
- Offline brute-force is cryptographically impossible (missing 256-bit pepper)
- Vault expires after configurable TTL (default: 72 hours)
- Offline: SDK refuses vault unseal (needs pepper), falls back to passphrase/PIN

**Threat model:**

| Attack | Mitigated by |
|--------|-------------|
| Offline brute-force (stolen device) | Server pepper (256-bit, never on device) |
| Online brute-force (at the device) | Server-side counter (3 attempts → wipe) |
| localStorage tampering | Counter on server, pepper on server |
| Server-only compromise | Password never sent to server, Argon2id output never sent |
| Network interception | TLS 1.2+, pepper delivered only over authenticated channel |
| Replay of server response | Nonce-bound pepper delivery (one-time use per attempt) |

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User with desktop PC (no biometrics) | Protect her secret with a device password |
| Bob | User who prefers password over biometrics | Explicit unlock rather than fingerprint |
| Eve | Attacker with physical access | Brute-force the vault password |
| SDK | 2FApi client WASM module | Seal/unseal secrets securely |
| Server | 2FApi backend | Track vault unseal attempts per device |

## Hypotheses

1. The vault password is distinct from the 2FApi passphrase/PIN (different purpose)
2. The vault password has no format restriction beyond minimum 8 characters
3. Argon2id parameters for vault: memory 64MB, iterations 3, parallelism 1 (same as passphrase derivation)
4. AES-256-GCM via Web Crypto API (SubtleCrypto) — native, constant-time
5. HKDF-SHA256 via Web Crypto API — standard key derivation
6. The server tracks vault unseal attempts per (client_id, device_id) pair
7. Vault unseal requires server validation — both for counter AND pepper delivery
8. Default TTL: 72 hours — admin-configurable per tenant (min: 1h, max: 720h)
9. Maximum 3 failed unseal attempts before server-triggered wipe + pepper destruction
10. The vault stores the derived secret (s, r) — NOT the passphrase/PIN
11. The server generates a random 256-bit pepper per device during vault seal
12. The pepper is stored server-side only — NEVER written to localStorage or sent in advance
13. The pepper is delivered to the SDK only during a validated unseal attempt (counter < threshold)
14. On wipe, the server destroys the pepper — the vault becomes permanently undecryptable
15. The SDK never sends the Argon2id output (ikm) to the server — only the server sends the pepper to the SDK
16. Salt for Argon2id: SHA-512(DST || email || tenant_id || device_id) — deterministic per device

---

## Vault Sealing

### Feature: Encrypting the derived secret with a device password

  As a user (Alice)
  I want to lock my derived secret behind a device password
  So that I don't need to type my passphrase at every login on this device

  Background:
    Given Alice is enrolled with passphrase "blue tiger fast moon"
    And the SDK just derived her secret and registered the commitment
    And Alice's device has no biometric hardware

  # --- Happy Path ---

  Scenario: Alice seals her secret with a device password
    Given the enrollment wizard shows "How do you want to protect this device?"
    And the options are:
      | Option | Available |
      | Biometrics (fingerprint/face) | No (no hardware) |
      | Device password | Yes |
      | No protection (shared device) | Yes |
    When Alice selects "Device password"
    And Alice enters password "MyD3v!ceP@ss"
    And Alice confirms password "MyD3v!ceP@ss"
    Then the SDK requests a pepper from the server: POST /v1/vault/seal { client_id, device_id }
    And the server generates a random 256-bit pepper and stores it per device
    And the server responds { "pepper": <256-bit>, "device_id": "dev-abc123" }
    And the SDK derives ikm via Argon2id from "MyD3v!ceP@ss"
    And the SDK derives vault_key via HKDF(ikm || pepper, ...)
    And the SDK encrypts (secret, blinding) with AES-256-GCM using vault_key
    And the encrypted vault is stored in localStorage["2fapi-vault"]
    And the password "MyD3v!ceP@ss" is NOT stored anywhere
    And the pepper is NOT stored on the device (zeroized after key derivation)
    And the derived secret is zeroized from WASM memory
    And Alice sees "Device password set. You can now sign in with your password."

  Scenario: Bob seals his secret after choosing password over biometrics
    Given Bob's device supports biometrics
    When enrollment offers protection options
    And Bob selects "Device password" (preferring explicit unlock)
    Then the vault is sealed with Bob's chosen password
    And the biometric store is NOT populated
    And Bob authenticates via password unlock in future sessions

  # --- Edge Cases ---

  Scenario: Password confirmation mismatch
    Given Alice types password "MyD3v!ceP@ss"
    When Alice types "MyD3v!cePAss" as confirmation
    Then the SDK rejects with "Passwords do not match"
    And Alice must re-enter both fields

  Scenario: Vault key derivation uses device-specific salt AND pepper
    Given Alice seals her vault on Device A with password "MyD3v!ceP@ss"
    And Alice seals her vault on Device B with the same password "MyD3v!ceP@ss"
    Then the vault keys are DIFFERENT (different device_id in salt + different pepper)
    And compromising Device A's vault does not help decrypt Device B's vault
    And even knowing Device A's pepper does not help with Device B

  Scenario: Pepper is zeroized from client memory after seal
    Given Alice seals her vault
    And the SDK received the pepper from the server
    And the SDK derived vault_key = HKDF(ikm || pepper, ...)
    When the vault is encrypted and stored in localStorage
    Then the pepper is overwritten with zeros in memory
    And the ikm is overwritten with zeros in memory
    And the vault_key is overwritten with zeros in memory
    And only the encrypted ciphertext remains (in localStorage)

  Scenario: Re-sealing replaces the existing vault
    Given Alice already has a sealed vault on this device
    When Alice goes to settings and selects "Change device password"
    And Alice enters her current device password to unseal
    And Alice enters a new password "N3wP@ssw0rd!"
    Then the old vault is deleted
    And a new vault is sealed with the new password
    And the server resets the attempt counter for this device

  # --- Error Cases ---

  Scenario: Password too short is rejected
    Given Alice types "abc" as device password
    Then the SDK rejects with "Password must be at least 8 characters"

  Scenario: Sealing fails if Web Crypto API unavailable
    Given the browser does not support SubtleCrypto (very old browser)
    When Alice selects "Device password"
    Then the SDK shows "This browser cannot encrypt securely. Please use a modern browser."
    And the vault is NOT created
    And Alice can still authenticate by typing her passphrase each time

  Scenario: Network failure during seal — vault created but server not notified
    Given Alice sealed her vault locally
    When the SDK tries to register the device_id on the server
    And the network is down
    Then the vault is stored locally (usable)
    And the SDK queues a pending device registration
    And the next successful server call completes the registration
    And until then, the vault unseal attempt counter is not enforced server-side

---

## Vault Unsealing

### Feature: Decrypting the stored secret with the device password

  As a user (Alice)
  I want to type my device password to unlock my secret
  So that I can authenticate without typing my 4-word passphrase

  Background:
    Given Alice has a sealed vault in localStorage
    And the vault was sealed with password "MyD3v!ceP@ss"

  # --- Happy Path ---

  Scenario: Successful vault unseal and authentication
    Given Alice navigates to the login page
    And the SDK detects a vault in localStorage for alice@acme.com
    When Alice enters her device password "MyD3v!ceP@ss"
    Then the SDK calls the server: POST /v1/vault/unseal-attempt { client_id, device_id }
    And the server responds { "pepper": <256-bit>, "attempts_remaining": 3, "status": "allowed" }
    And the SDK derives ikm via Argon2id from "MyD3v!ceP@ss"
    And the SDK derives vault_key via HKDF(ikm || pepper, ...)
    And the SDK decrypts the vault with AES-256-GCM
    And the SDK recovers (secret, blinding) from the decrypted payload
    And the pepper and ikm are zeroized from memory
    And the SDK requests a challenge nonce from the server
    And the SDK computes a Sigma proof
    And the server verifies the proof
    And Alice is logged in and receives a JWT
    And the secret is zeroized from WASM memory
    And the server resets the vault attempt counter to 0

  Scenario: Vault detected — SDK shows password input instead of passphrase
    Given Alice's vault exists in localStorage
    When the login page loads for alice@acme.com
    Then the SDK shows a password input field (not the 4-word passphrase fields)
    And a link "Use passphrase instead" is available
    And clicking "Use passphrase instead" shows the 4-word input fields

  Scenario: Fallback to passphrase after vault unseal
    Given Alice clicks "Use passphrase instead"
    When Alice types "blue tiger fast moon"
    Then authentication proceeds via passphrase derivation (bypassing the vault)
    And the vault remains sealed in localStorage (not deleted)

  # --- Edge Cases ---

  Scenario: Vault TTL expired — must re-seal
    Given Alice's vault was created 73 hours ago (TTL = 72h)
    When the SDK loads and checks the vault
    Then the SDK deletes the expired vault
    And Alice must type her passphrase to authenticate
    And after successful auth, the SDK offers to re-seal with a device password

  Scenario: Server reachable but slow — unseal waits for server response
    Given Alice entered her device password
    When the SDK calls the server for attempt validation
    And the server takes 3 seconds to respond
    Then the SDK shows "Verifying..." and does NOT attempt decryption
    And decryption only proceeds after server confirms "allowed"

  Scenario: Multiple vaults for different accounts on same device
    Given Alice has a vault for alice@acme.com
    And Bob has a vault for bob@acme.com
    When Alice enters her email alice@acme.com
    Then only Alice's vault is offered for password unlock
    And Bob's vault is untouched

  # --- Error Cases ---

  Scenario: Wrong device password
    Given Alice enters password "WrongP@ss123"
    When the server responds with pepper and { "attempts_remaining": 2, "status": "allowed" }
    And the SDK derives vault_key from "WrongP@ss123" + pepper
    And AES-256-GCM decryption fails (authentication tag mismatch)
    Then Alice sees "Wrong password. 2 attempts remaining."
    And the SDK notifies the server: POST /v1/vault/unseal-failed { client_id, device_id }
    And the server increments the failure counter for this device
    And the pepper is zeroized from client memory

  Scenario: Vault unseal refused — server says wiped and destroys pepper
    Given Eve has already failed 3 times on this device
    When Eve enters another password
    And the SDK calls the server: POST /v1/vault/unseal-attempt
    And the server responds { "attempts_remaining": 0, "status": "wiped" }
    Then the server has DESTROYED the pepper for this device (permanently)
    And the SDK deletes localStorage["2fapi-vault"]
    And Eve sees "This vault has been locked. Sign in with your passphrase."
    And the passphrase input fields are shown
    And even if Eve restores the vault blob from backup, it is permanently undecryptable

  Scenario: Vault unseal offline — refused
    Given Alice's device has no network connection
    When Alice enters her device password
    Then the SDK refuses with "Server verification required to unlock vault"
    And a link "Use passphrase instead" is shown
    And Alice can authenticate via passphrase (Argon2id runs locally)
    And the vault is NOT deleted (will work when online again)

  Scenario: Vault corrupted in localStorage
    Given someone (or a bug) modified the vault ciphertext in localStorage
    When Alice enters the correct password
    And AES-256-GCM decryption fails (tag mismatch due to corruption)
    Then the SDK detects the corruption
    And the SDK deletes the corrupted vault
    And Alice must authenticate via passphrase
    And Alice is offered to re-seal after successful auth

---

## Server-Side Attempt Counter & Pepper

### Feature: Tracking vault unseal attempts and delivering pepper securely

  As the 2FApi server
  I want to track failed vault unseal attempts per device and deliver the pepper only when allowed
  So that attackers cannot brute-force the device password (online or offline)

  Background:
    Given the vault attempt threshold is 3 (configurable by admin)
    And Alice has a sealed vault on Device A (device_id: "dev-abc123")
    And the server holds a 256-bit pepper for Device A

  # --- Happy Path ---

  Scenario: Server allows attempt and delivers pepper
    Given Alice has 0 failed attempts on Device A
    When the SDK sends POST /v1/vault/unseal-attempt { client_id, device_id }
    Then the server responds { "pepper": <256-bit>, "attempts_remaining": 3, "status": "allowed" }
    And the SDK proceeds with key derivation and decryption

  Scenario: Server resets counter after successful auth
    Given Alice failed 2 vault unseal attempts on Device A
    When Alice authenticates successfully (via vault or passphrase)
    Then the server resets the vault attempt counter for Device A to 0
    And Alice has 3 attempts available again

  # --- Edge Cases ---

  Scenario: Counter is per-device, not per-account
    Given Alice has 2 failures on Device A
    And Alice has 0 failures on Device B
    When Eve fails a 3rd time on Device A
    Then Device A's vault is wiped
    And Device B's vault is unaffected (still 0 failures, 3 remaining)

  Scenario: Admin configures threshold to 5
    Given Carol set the vault attempt threshold to 5 for "Acme Corp"
    When someone fails 4 times on Bob's Device A
    Then no wipe occurs (1 attempt remaining)
    And the server responds { "attempts_remaining": 1, "status": "allowed" }

  Scenario: Successful passphrase login also resets vault counter
    Given Alice failed 2 vault unseal attempts
    When Alice clicks "Use passphrase instead" and authenticates successfully
    Then the vault attempt counter resets to 0
    And Alice can try her vault password again (3 attempts)

  Scenario: Admin can manually reset a device's vault counter
    Given Eve triggered a vault wipe on Alice's Device A
    And Alice contacts support
    When Carol (admin) resets Alice's vault counter for Device A via admin API
    Then Alice can re-seal her vault on Device A after authenticating via passphrase

  # --- Error Cases ---

  Scenario: Attacker resets localStorage counter manually
    Given Eve opens the browser developer console
    And Eve tampers with any local attempt counter or vault metadata
    When Eve tries another password
    Then the SDK sends POST /v1/vault/unseal-attempt to the server
    And the server uses ITS counter (not localStorage)
    And the server reports the real failure count
    And Eve cannot bypass the limit regardless of local tampering

  Scenario: Server unreachable — unseal blocked (no pepper available)
    Given Alice's device is offline
    When the SDK attempts POST /v1/vault/unseal-attempt
    And the request fails (network error)
    Then the SDK CANNOT attempt decryption (no pepper = impossible)
    And Alice sees "Server verification required to unlock vault"
    And Alice can use passphrase fallback (Argon2id runs locally)
    And the vault is NOT deleted (will work when online again)

  Scenario: Replay of old server pepper response blocked
    Given Eve intercepts a previous response containing the pepper
    When Eve replays the response to the SDK
    Then the SDK detects the stale nonce/timestamp in the signed response
    And the unseal attempt is rejected
    And the intercepted pepper is useless (bound to a one-time challenge)

  Scenario: Concurrent unseal attempts on same device
    Given Eve opens two browser tabs for alice@acme.com
    When Eve submits a password in both tabs simultaneously
    Then the server serializes the attempts (atomic counter increment)
    And each tab gets a correct, sequential attempt count
    And no race condition allows extra attempts

  Scenario: Pepper delivery is authenticated and encrypted
    Given Alice sends POST /v1/vault/unseal-attempt over TLS
    When the server responds with the pepper
    Then the pepper is delivered inside the TLS channel (encrypted in transit)
    And the response is signed with the server's key (authenticated)
    And a MITM attacker who breaks TLS sees only the pepper (still needs password)
    And the pepper alone is insufficient to decrypt the vault

---

## Vault Lifecycle & TTL

### Feature: Managing vault expiry and lifecycle events

  As the 2FApi client SDK
  I want to enforce vault TTL and handle lifecycle transitions
  So that stale vaults do not accumulate and the security posture is maintained

  Background:
    Given the default vault TTL is 72 hours (configurable by admin)

  # --- Happy Path ---

  Scenario: Vault TTL displayed to user
    Given Alice sealed her vault 48 hours ago
    When Alice unlocks her vault
    Then the SDK silently checks the TTL (24 hours remaining)
    And authentication proceeds normally
    And no warning is shown (more than 12 hours remaining)

  Scenario: Vault approaching expiry shows warning
    Given Alice sealed her vault 66 hours ago
    When Alice unlocks her vault (6 hours remaining)
    Then the SDK shows "Your device password will expire in 6 hours"
    And offers "Renew now" (re-seal with same or new password)
    And Alice can renew or dismiss

  # --- Edge Cases ---

  Scenario: Admin reduces TTL — existing vaults affected
    Given Alice's vault was sealed with TTL 72h
    And Carol changes the tenant policy to vault_ttl: 24h
    When Alice visits the login page 30 hours after sealing
    Then the SDK checks the server for current TTL policy
    And the server says the vault has exceeded the new 24h TTL
    And the SDK deletes the vault
    And Alice must re-authenticate with her passphrase

  Scenario: Admin disables vault storage for tenant
    Given Carol changes the tenant policy to "vault_storage: disabled"
    When Alice visits the login page
    Then the SDK detects the policy change from the server
    And the SDK deletes all vault data from localStorage
    And Alice sees "Your organization no longer allows device password storage"
    And Alice must use her passphrase from now on

  Scenario: User explicitly deletes vault from settings
    Given Alice is authenticated
    When Alice goes to security settings
    And selects "Remove device password"
    Then the vault is deleted from localStorage
    And the server is notified (device vault registration removed)
    And Alice must use passphrase or re-enable vault/biometrics

  # --- Error Cases ---

  Scenario: Clock manipulation does not bypass TTL
    Given Alice's vault was created with created_at = server timestamp
    When Eve sets the device clock back to extend the vault's apparent lifetime
    Then the SDK checks the server for the authoritative time
    And the server compares created_at against its own clock
    And if expired, the server responds with "vault_expired"
    And the SDK deletes the vault

  Scenario: localStorage full — vault cannot be created
    Given localStorage is at its 5MB browser limit
    When the SDK attempts to store the vault
    Then the SDK catches the QuotaExceededError
    And Alice sees "Cannot store vault: device storage full"
    And Alice can authenticate via passphrase (no vault needed)
    And the SDK suggests clearing browser data or using passphrase mode

  Scenario: Vault migration on SDK upgrade
    Given Alice has a vault created by SDK v1
    When Alice loads a page with SDK v2 (new vault format)
    Then the SDK detects the old vault format
    And the SDK prompts Alice to re-enter her device password
    And the SDK decrypts with the old format, re-encrypts with the new format
    And the vault is seamlessly migrated

---

## Offline Attack Resistance

### Feature: Ensuring the vault cannot be cracked without server cooperation

  As the 2FApi security model
  I want to guarantee that a stolen device with a vault cannot be brute-forced offline
  So that the password-locked vault provides real security, not just convenience

  # --- Happy Path ---

  Scenario: Vault is cryptographically uncrackable offline
    Given Eve stole Alice's laptop and disabled the network
    And Eve extracted the encrypted vault from localStorage
    And Eve extracted the SDK JavaScript source code (public algorithm)
    When Eve runs an offline brute-force: for each candidate password,
      derive ikm = Argon2id(candidate, salt), then key = HKDF(ikm, ...)
    Then EVERY candidate produces a WRONG AES key
    Because the key derivation requires HKDF(ikm || pepper, ...)
    And the pepper (256 bits of entropy) is stored only on the server
    And Eve cannot reconstruct the pepper from the vault blob
    And the vault ciphertext is indistinguishable from random noise without the pepper

  # --- Edge Cases ---

  Scenario: Eve knows Alice's password but not the pepper
    Given Eve observed Alice typing "MyD3v!ceP@ss"
    And Eve stole the laptop and took it offline
    When Eve derives ikm = Argon2id("MyD3v!ceP@ss", salt)
    Then Eve has the correct ikm but CANNOT derive vault_key
    Because vault_key = HKDF(ikm || pepper, ...) and pepper is 256 bits unknown
    And brute-forcing 256 bits of pepper is computationally infeasible (2^256 attempts)

  Scenario: Eve compromises the server but not the device password
    Given Eve breached the 2FApi server and extracted the pepper for Device A
    And Eve has the encrypted vault from Alice's localStorage
    When Eve attempts to decrypt the vault with the pepper alone
    Then decryption fails because vault_key = HKDF(ikm || pepper, ...)
    And ikm = Argon2id(password, ...) requires Alice's password
    And Eve must still brute-force the password (Argon2id at 500ms/attempt)
    And both factors (password + pepper) are required

  # --- Error Cases ---

  Scenario: Eve copies the vault blob and tries to restore after wipe
    Given Eve failed 3 times and the vault was wiped
    And Eve had previously copied the vault blob from localStorage
    When Eve restores the vault blob to localStorage
    Then the server has DESTROYED the pepper for this device
    And Eve's POST /v1/vault/unseal-attempt returns { "status": "wiped" }
    And even with the correct password, the vault is permanently undecryptable
    And Eve cannot re-register a new pepper without authenticating first

  Scenario: Eve extracts WASM memory during Argon2id computation
    Given Eve attached a debugger while Alice was typing her password
    And Eve captured the Argon2id output (ikm) from WASM memory
    When Eve takes the device offline
    Then Eve has ikm but still needs the pepper
    And Eve cannot contact the server (offline)
    And if Eve goes online, the attempt counter still applies (3 max)
    And if already wiped, the pepper is destroyed permanently

  Scenario: Eve clones the device and makes unlimited copies
    Given Eve cloned Alice's device (full disk copy) 3 times
    And each clone has the same vault blob
    When Eve tries 3 passwords on Clone 1, triggering a wipe
    Then the server destroys the pepper for dev-abc123
    And Clone 2 and Clone 3 also cannot unseal (same device_id, pepper destroyed)
    And Eve gained only 3 total attempts regardless of the number of clones
