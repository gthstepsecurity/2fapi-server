# BDD Scenarios — OPRF + Hardware-Bound Vault (Tier 1b / Tier 2+)

> Generated on 2026-03-26 via BDD Workshop + Expert Review + Founder Design Session
> Source: Founder insight — FHE-style oblivious derivation + hardware binding

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| OPRF Key Derivation | 2 | 12 | 3 | 4 | 5 |
| Hardware-Bound Key (WebAuthn PRF) | 2 | 10 | 3 | 3 | 4 |
| Combined 3-Factor Vault | 2 | 12 | 3 | 4 | 5 |
| OPRF Server-Side Management | 2 | 8 | 2 | 3 | 3 |
| Protocol Integrity | 2 | 8 | 2 | 3 | 3 |
| **Total** | **10** | **50** | **13** | **17** | **20** |

## Context

The vault encryption key is derived from THREE independent factors using an
Oblivious Pseudo-Random Function (OPRF) and a hardware-bound key:

```
Factor 1: Password (something you know)
    → never leaves the client, never sent to server (not even hashed)

Factor 2: OPRF key (something the server holds)
    → server evaluates blindly, never sees the password
    → client receives result, never sees the OPRF key

Factor 3: Hardware key (something the device has)
    → derived via WebAuthn PRF extension (Secure Enclave / TPM)
    → never leaves the hardware, requires biometric/PIN each time
    → OPTIONAL: falls back to Tier 1 (OPRF-only) if no hardware support
```

### Cryptographic Protocol

```
OPRF over Ristretto255 (RFC 9497 / VOPRF):

  Client:
    P = hash_to_curve(password)       # deterministic mapping
    r ← random scalar                 # blinding factor
    B = r · P                         # blinded element

  Server (receives B, has oprf_key k):
    E = k · B                         # scalar multiplication (blind evaluation)

  Client (receives E):
    U = r⁻¹ · E = k · P              # unblind = OPRF(k, password)
    (server never saw P or password; client never saw k)

  Hardware (optional, via WebAuthn PRF):
    hw_key = PRF(credential_id, "2fapi-vault-hw-v1")   # hardware-bound

  Key derivation:
    vault_key = HKDF-SHA256(
      ikm = U || hw_key,              # OPRF output + hardware key
      salt = device_id,
      info = "2fapi-vault-seal-v1"
    )
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| Zero-knowledge of password to server | Server sees only blinded point B (random-looking) |
| Zero-knowledge of OPRF key to client | Client sees only evaluated point E (cannot recover k) |
| Hardware binding | hw_key never leaves Secure Enclave; requires biometric per use |
| Offline brute-force | Impossible: missing OPRF key (256-bit) AND hardware key |
| Online brute-force | Server-side attempt counter (3 tries → wipe OPRF key) |
| Server compromise | OPRF keys alone useless without password + hardware |
| Browser compromise | OPRF output U visible briefly; useless without hw_key (Secure Enclave) |
| Replay of server response | Blinding factor r is fresh each time; replayed E unblinds to wrong value |

### Tier Refinement

```
Tier 0  — Shared device     : passphrase/PIN → Argon2id → proof → zeroize
Tier 1a — OPRF vault        : password + OPRF(server) → AES-GCM vault (no hardware)
Tier 1b — OPRF+HW vault     : password + OPRF(server) + WebAuthn PRF(hardware) → vault
Tier 2  — Biometric-only    : WebAuthn → secret from Credential Manager → proof
```

Tier 1b is the strongest vault option: 3-factor protection.
Tier 1a is the fallback when hardware PRF is unavailable.

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User with biometric hardware (supports PRF extension) | Authenticate with 3-factor vault |
| Bob | User without biometric hardware | Authenticate with 2-factor OPRF vault (Tier 1a) |
| Eve | Attacker who stole Alice's laptop | Attempt offline brute-force |
| Mallory | Active network attacker (MITM) | Intercept OPRF messages |
| Server | 2FApi backend | Evaluate OPRF blindly, manage OPRF keys |
| SDK | 2FApi client WASM module | Blind, unblind, derive key, encrypt/decrypt |

## Hypotheses

1. OPRF uses Ristretto255 (same curve as Pedersen/Sigma) — no new dependency
2. The OPRF evaluation is a single scalar multiplication: E = k · B (~1ms)
3. The blinding factor r is fresh random for each unseal attempt (no replay)
4. WebAuthn PRF extension (`hmac-secret`) is available on Chrome 116+, Safari 17+
5. When PRF extension is unavailable, fall back to Tier 1a (OPRF-only, 2-factor)
6. The OPRF key is per (client_id, device_id) — same granularity as the current pepper
7. On wipe (3 failures), the server destroys the OPRF key permanently
8. The blinded point B reveals zero information about the password (DDH assumption)
9. The OPRF protocol runs over the existing TLS channel (no additional encryption needed)
10. The hash-to-curve function uses Ristretto255 Elligator (RFC 9380)

---

## OPRF Key Derivation

### Feature: Deriving the vault key via oblivious evaluation without exposing password or server key

  As a user (Alice)
  I want the vault key to be derived without the server learning my password
  So that even a compromised server cannot brute-force my vault

  Background:
    Given Alice has a sealed vault on this device
    And the server holds an OPRF key k for this device

  # --- Happy Path ---

  Scenario: Successful OPRF-based vault key derivation
    Given Alice enters her device password "MyD3v!ceP@ss"
    When the SDK computes P = hash_to_curve("MyD3v!ceP@ss")
    And the SDK generates a random blinding factor r
    And the SDK computes B = r · P (blinded point)
    And the SDK sends B to the server: POST /v1/vault/oprf-evaluate
    And the server computes E = k · B (blind evaluation)
    And the server returns E (along with attempt counter status)
    And the SDK computes U = r⁻¹ · E (unblinds)
    Then U = k · P = OPRF(k, password) and is deterministic for same password
    And the SDK uses U as input to HKDF for the vault key
    And the password never left the client (not even as a hash)
    And the OPRF key k never left the server

  Scenario: OPRF output is deterministic for the same password
    Given Alice uses password "MyD3v!ceP@ss" on two separate logins
    When the SDK performs the OPRF protocol both times (with different blinding r)
    Then both unblindings produce the same U = k · hash_to_curve("MyD3v!ceP@ss")
    And the same vault key is derived
    And the vault decrypts successfully both times

  Scenario: Different passwords produce different OPRF outputs
    Given Alice uses "MyD3v!ceP@ss" and Eve uses "WrongP@ss!"
    When both perform the OPRF protocol with the same server OPRF key
    Then hash_to_curve("MyD3v!ceP@ss") ≠ hash_to_curve("WrongP@ss!")
    And the OPRF outputs U₁ ≠ U₂
    And the vault keys are different
    And Eve's key fails to decrypt Alice's vault (GCM tag mismatch)

  # --- Edge Cases ---

  Scenario: Blinding factor prevents server from learning password
    Given Alice sends blinded point B to the server
    When the server observes B
    Then B = r · hash_to_curve(password) where r is random
    And without r, the server cannot recover hash_to_curve(password)
    And the server cannot perform a dictionary attack against B
    And this holds under the Decisional Diffie-Hellman assumption on Ristretto255

  Scenario: Fresh blinding prevents replay of server response
    Given Eve intercepted a previous OPRF response E₁ (from blinding r₁)
    When Alice performs a new OPRF with fresh blinding r₂
    And Eve replays E₁ instead of the real E₂
    Then Alice unblinds: r₂⁻¹ · E₁ ≠ r₁⁻¹ · E₁ = U
    And the wrong vault key is derived
    And AES-GCM decryption fails (tag mismatch)
    And Alice sees "Wrong password" (indistinguishable from actual wrong password)

  Scenario: OPRF evaluation is fast (< 5ms total)
    Given the OPRF requires one scalar multiplication on each side
    When the SDK computes blinding and unblinding in WASM
    And the server computes the evaluation
    Then the client-side crypto takes < 2ms
    And the server-side crypto takes < 1ms
    And the total OPRF overhead is dominated by network latency, not crypto

  Scenario: OPRF runs inside WASM — intermediate values never in JS
    Given the SDK performs the OPRF protocol
    When the blinding, hash_to_curve, and unblinding are computed
    Then all scalar operations (r, r⁻¹, P, B, U) are in WASM linear memory
    And only the blinded point B (32 bytes, public-looking) crosses to JS for network
    And only the evaluated point E (32 bytes, public-looking) crosses back
    And the unblinded result U is used directly in WASM for HKDF
    And U never crosses the WASM↔JS boundary

  # --- Error Cases ---

  Scenario: Server returns invalid evaluated point
    Given a buggy or malicious server returns a non-canonical point E
    When the SDK validates E before unblinding
    Then the SDK detects the invalid point (decompression fails)
    And the unseal attempt is aborted
    And Alice sees "Server returned invalid data. Please try again."
    And no partial key derivation occurs

  Scenario: Server returns identity point (trivial OPRF key)
    Given a compromised server returns E = identity (k = 0)
    When the SDK checks E for identity
    Then the SDK rejects: "OPRF evaluation produced identity element"
    And the unseal is aborted (this would mean k = 0, which is a backdoor)
    And the incident is logged for security monitoring

  Scenario: Blinding factor is zero (degenerate case)
    Given a random number generator produces r = 0
    When the SDK computes B = 0 · P = identity
    Then the SDK detects B is the identity point
    And the SDK regenerates r and retries (transparent to user)
    And the degenerate case never reaches the server

  Scenario: Network interceptor modifies blinded point B
    Given Mallory intercepts and modifies B in transit
    When the server evaluates E = k · B' (modified point)
    And the SDK unblinds with the original r
    Then the result U' is garbage (not OPRF(k, password))
    And the vault key is wrong
    And AES-GCM decryption fails
    And Alice sees "Wrong password" (MITM is indistinguishable from wrong password)

  Scenario: OPRF protocol with server unreachable
    Given Alice's device has no network connection
    When the SDK cannot send B to the server
    Then the OPRF cannot proceed (server evaluation is required)
    And Alice sees "Server required. Use passphrase instead."
    And Alice falls back to Tier 0 (direct Argon2id derivation, needs server for challenge)

---

## Hardware-Bound Key (WebAuthn PRF)

### Feature: Binding the vault key to the device's hardware secure element

  As a user (Alice) on a device with biometric hardware
  I want my vault key to include a hardware-bound factor
  So that stealing my device is not enough to brute-force the vault

  Background:
    Given Alice's device supports WebAuthn with the PRF extension (hmac-secret)

  # --- Happy Path ---

  Scenario: Hardware key derived via WebAuthn PRF during seal
    Given Alice is sealing her vault
    When the SDK creates a WebAuthn credential with the PRF extension
    And Alice confirms with her fingerprint
    Then the SDK calls credential.getClientExtensionResults().prf
    And receives hw_key = PRF(credential, "2fapi-vault-hw-v1")
    And hw_key is 256 bits, derived inside the secure element
    And hw_key is combined with the OPRF output: vault_key = HKDF(U || hw_key)
    And the vault is encrypted with vault_key

  Scenario: Hardware key retrieved via WebAuthn PRF during unseal
    Given Alice is unsealing her vault
    And the OPRF output U was computed
    When the SDK calls navigator.credentials.get() with PRF extension
    And Alice touches her fingerprint sensor
    Then the same hw_key is derived (deterministic PRF)
    And vault_key = HKDF(U || hw_key) matches the seal-time key
    And the vault decrypts successfully

  Scenario: Same credential, same PRF input → same hw_key
    Given Alice sealed her vault with hw_key
    When Alice unseals on a subsequent login with the same credential
    Then the PRF output is identical (deterministic)
    And the vault key matches
    And decryption succeeds

  # --- Edge Cases ---

  Scenario: PRF extension not available — fallback to Tier 1a (OPRF-only)
    Given Bob's device supports WebAuthn but NOT the PRF extension
    When the SDK checks for PRF support during seal
    Then the SDK skips the hardware key factor
    And vault_key = HKDF(U, device_id) — 2-factor (password + OPRF)
    And Bob is informed: "Your device does not support hardware binding. Vault is protected by password + server."

  Scenario: Hardware key changes after credential re-creation
    Given Alice re-enrolled biometrics (new WebAuthn credential)
    When the SDK tries to unseal with the new credential
    Then the new PRF output is DIFFERENT from the old one (different credential ID)
    And the old vault cannot be decrypted
    And Alice must re-seal the vault after authenticating via passphrase

  Scenario: WebAuthn PRF requires user verification each time
    Given Alice tries to derive the hardware key
    When the SDK calls credentials.get() with userVerification: "required"
    Then Alice must touch her fingerprint sensor (no silent access)
    And the PRF is only evaluated after biometric confirmation
    And a malicious script cannot silently extract hw_key

  # --- Error Cases ---

  Scenario: Biometric fails — PRF not available, vault locked
    Given Alice's fingerprint is not recognized 3 times
    When the WebAuthn prompt times out
    Then the SDK cannot derive hw_key
    And the vault cannot be decrypted (missing hardware factor)
    And Alice falls back to Tier 0 (type passphrase, Argon2id derivation)

  Scenario: Secure element hardware failure
    Given the TPM/Secure Enclave malfunctions
    When the SDK calls credentials.get() and receives an error
    Then Alice sees "Hardware security module error. Use passphrase instead."
    And the vault remains sealed (not deleted — hardware may recover)
    And Alice authenticates via Tier 0

  Scenario: Extension tries to intercept WebAuthn PRF
    Given a malicious extension hooks navigator.credentials.get()
    When the extension wraps the call
    Then the extension sees the credential assertion (public key, signature)
    But the PRF output (hw_key) is in the clientExtensionResults
    And the extension CAN read clientExtensionResults from JS
    And MITIGATION: hw_key alone is insufficient (needs OPRF output U too)
    And U is inside WASM memory (never crosses to JS)
    And the attacker needs BOTH factors simultaneously — defense in depth

  Scenario: Device cloned (full disk image) — hardware key not portable
    Given Eve clones Alice's laptop disk
    When Eve boots the clone on different hardware
    Then the WebAuthn credential is bound to the ORIGINAL hardware's TPM
    And the clone's TPM does not have the credential
    And PRF evaluation fails on the clone
    And the vault is undecryptable on the cloned hardware

---

## Combined 3-Factor Vault

### Feature: Sealing and unsealing a vault with password + OPRF + hardware

  As a user (Alice)
  I want my vault protected by three independent factors
  So that compromising any two is still insufficient to access my secret

  Background:
    Given Alice's device supports WebAuthn PRF
    And the server holds an OPRF key for Alice's device

  # --- Happy Path ---

  Scenario: Seal vault with 3 factors
    Given Alice completed enrollment and derived her secret
    When Alice chooses "Device password" at the protection step
    And Alice types password "MyD3v!ceP@ss"
    Then the SDK performs OPRF: blind → server evaluate → unblind → U
    And the SDK derives hw_key via WebAuthn PRF (fingerprint confirm)
    And the SDK derives vault_key = HKDF(U || hw_key, device_id)
    And the SDK encrypts (secret, blinding) with AES-256-GCM using vault_key
    And the vault is stored in localStorage
    And password, U, hw_key, and vault_key are all zeroized
    And Alice sees "Vault sealed with 3-factor protection"

  Scenario: Unseal vault with 3 factors
    Given Alice's vault is sealed in localStorage
    When Alice enters her password "MyD3v!ceP@ss"
    And the SDK performs OPRF: blind → server evaluate (counter check) → unblind → U
    And the SDK derives hw_key via WebAuthn PRF (fingerprint confirm)
    And the SDK derives vault_key = HKDF(U || hw_key, device_id)
    And the SDK decrypts the vault
    Then Alice's secret is recovered
    And the SDK computes the proof in WASM
    And all key material is zeroized
    And Alice is authenticated

  Scenario: Unseal with 2 factors (no hardware) on Tier 1a device
    Given Bob's device has no PRF support
    And Bob's vault was sealed with 2 factors (password + OPRF)
    When Bob enters his password
    And the OPRF completes
    Then vault_key = HKDF(U, device_id) — 2-factor
    And the vault decrypts successfully
    And Bob is authenticated

  # --- Edge Cases ---

  Scenario: Eve has password + OPRF output but not hardware
    Given Eve observed Alice's password and intercepted the OPRF output U
    When Eve tries to decrypt the vault
    Then Eve is missing hw_key (requires Alice's hardware + fingerprint)
    And vault_key = HKDF(U || hw_key) cannot be derived without hw_key
    And hw_key is 256 bits of entropy from the secure element
    And brute-forcing hw_key is computationally infeasible

  Scenario: Eve has password + hardware but not OPRF
    Given Eve stole Alice's laptop (has hardware) and knows the password
    When Eve tries to unseal offline
    Then Eve can derive hw_key (has the hardware + password for biometric)
    But Eve is missing the OPRF output U (requires server evaluation)
    And without network access, U cannot be obtained
    And the vault is indecryptable offline

  Scenario: Eve compromised the server and has the OPRF key
    Given Eve breached the server and extracted OPRF key k
    When Eve tries to compute U = k · hash_to_curve(password)
    Then Eve must guess the password (Argon2id equivalent hardness for hash_to_curve)
    And even with U, Eve needs hw_key (requires physical device + biometric)
    And compromising server + guessing password is STILL insufficient without hardware

  Scenario: Vault downgrade from 3-factor to 2-factor
    Given Alice's hardware stopped supporting PRF (OS update regression)
    When Alice tries to unseal and PRF fails
    Then Alice falls back to Tier 0 (passphrase)
    And after successful auth, Alice is offered to re-seal at Tier 1a (2-factor)
    And the old 3-factor vault is deleted (undecryptable without PRF)

  # --- Error Cases ---

  Scenario: OPRF succeeds but WebAuthn PRF fails
    Given the OPRF evaluation returned U
    When Alice's fingerprint is not recognized
    And WebAuthn PRF fails
    Then U is zeroized immediately
    And the vault cannot be opened (missing hw_key factor)
    And Alice falls back to Tier 0 (passphrase)
    And the OPRF attempt is NOT counted as a failure (the password was correct)

  Scenario: WebAuthn PRF succeeds but OPRF server is down
    Given Alice touched her fingerprint and hw_key was derived
    When the server is unreachable for OPRF evaluation
    Then hw_key is zeroized immediately
    And Alice sees "Server required for vault unlock"
    And Alice falls back to Tier 0

  Scenario: Wrong password — detected at OPRF stage
    Given Eve enters the wrong password
    When the SDK computes B = r · hash_to_curve(wrong_password)
    And the server evaluates E = k · B
    And the SDK unblinds: U_wrong = r⁻¹ · E
    Then U_wrong ≠ U_correct (different password → different OPRF output)
    And vault_key is wrong
    And AES-GCM decryption fails (tag mismatch)
    And the server increments the failure counter
    And Eve sees "Wrong password. N attempts remaining."

  Scenario: All 3 failures consumed — OPRF key destroyed
    Given the failure counter reached 3
    When the server triggers a wipe
    Then the OPRF key k is permanently deleted
    And even with the correct password + hardware, the vault is undecryptable
    And Alice must re-enroll via passphrase and re-seal the vault

  Scenario: Concurrent OPRF evaluations serialized by server
    Given Eve submits two blind evaluations simultaneously
    When the server receives both
    Then the server serializes them (atomic counter increment)
    And each evaluation increments the counter independently
    And no race condition allows extra attempts

---

## OPRF Server-Side Management

### Feature: Managing OPRF keys and evaluation on the server

  As the 2FApi server
  I want to generate, store, and evaluate OPRF keys per device
  So that the oblivious key derivation is secure and auditable

  Background:
    Given the server stores OPRF keys in the vault_oprf_keys table

  # --- Happy Path ---

  Scenario: Server generates OPRF key during vault seal
    Given Alice requests a vault seal
    When the server receives POST /v1/vault/seal
    Then the server generates a random 256-bit scalar k (the OPRF key)
    And stores k in the database per (client_id, device_id)
    And responds with status "ready" (NOT the key — client never sees k)
    And the client proceeds to the OPRF evaluation step

  Scenario: Server evaluates OPRF blindly
    Given Alice sends blinded point B to POST /v1/vault/oprf-evaluate
    And the server retrieves OPRF key k for (client_id, device_id)
    When the server computes E = k · B
    Then the server returns E (32 bytes, compressed Ristretto point)
    And the server logs: "oprf_evaluation: client_id, device_id, timestamp"
    And the server does NOT log B or E (they are ephemeral)

  # --- Edge Cases ---

  Scenario: OPRF evaluation checks attempt counter first
    Given Alice has 2 failures on this device
    When Alice sends a new OPRF evaluation request
    Then the server checks the attempt counter (2 < 3 threshold)
    And the server evaluates E = k · B
    And responds with { evaluated: E, attempts_remaining: 1 }

  Scenario: Server rotates OPRF key on vault re-seal
    Given Alice re-seals her vault (new password)
    When the server receives a new seal request
    Then the server generates a fresh OPRF key k'
    And replaces the old key k
    And resets the attempt counter to 0

  Scenario: OPRF key is separate from Pedersen commitment
    Given Alice's Pedersen commitment C is stored for authentication
    And Alice's OPRF key k is stored for vault protection
    Then C and k are independent (different purposes)
    And compromising k does not help forge proofs (C is unrelated)
    And compromising C does not help decrypt the vault (k is unrelated)

  # --- Error Cases ---

  Scenario: OPRF evaluation refused after wipe
    Given the attempt counter triggered a wipe
    When Eve sends an OPRF evaluation request
    Then the server responds { status: "wiped" }
    And the OPRF key has been permanently deleted
    And no evaluation is performed

  Scenario: Invalid blinded point rejected
    Given Eve sends a non-canonical or identity point as B
    When the server validates B
    Then the server rejects with "invalid blinded element"
    And no evaluation is performed
    And the attempt counter is NOT incremented (malformed request, not a password attempt)

  Scenario: OPRF key not found (no vault registered)
    Given Dave has no vault on this device
    When Dave sends an OPRF evaluation request
    Then the server responds with 404 "no vault registered for this device"

---

## Protocol Integrity

### Feature: Ensuring the OPRF protocol is not subverted

  As the 2FApi security model
  I want mathematical guarantees that the OPRF is sound
  So that the zero-knowledge and oblivious properties hold

  # --- Happy Path ---

  Scenario: OPRF correctness — same password always produces same key
    Given Alice uses password P and the server has OPRF key k
    When Alice performs N OPRF evaluations with different blinding factors r₁...rₙ
    Then all N unblindings produce the same U = k · hash_to_curve(P)
    And the vault key is the same every time
    And this is a property-based test: ∀r, unblind(evaluate(blind(P, r), k), r) = k · H(P)

  Scenario: OPRF obliviousness — server learns nothing from B
    Given the server sees blinded point B = r · H(password)
    Then B is uniformly random on the Ristretto255 group (for random r)
    And no polynomial-time algorithm can distinguish B from a random point
    And this holds under the DDH assumption on Ristretto255
    And a property-based test verifies: ∀p₁,p₂, distribution of blind(p₁,r) ≈ distribution of blind(p₂,r)

  # --- Edge Cases ---

  Scenario: Non-malleability — modified proof detected
    Given Eve intercepts Alice's Sigma proof (96 bytes)
    When Eve flips a single bit in the proof
    Then the server's proof verification fails
    And the modified proof is indistinguishable from a random wrong proof
    And Eve cannot create a valid proof from a modified one (unforgeability under DLOG)

  Scenario: Protocol version mismatch detected
    Given the WASM module uses protocol v2 for the Fiat-Shamir transcript
    And the server expects protocol v1
    When Alice sends a proof computed with v2 transcript
    Then the server rejects: "unsupported protocol version"
    And Alice sees "Please update your app"
    And the SDK can negotiate the version via a header

  Scenario: Hash-to-curve is domain-separated
    Given the OPRF uses hash_to_curve for password mapping
    And the Sigma protocol uses hash_to_curve for challenge derivation
    When both use SHA-512 internally
    Then the domain separation tags are different:
      | Context | DST |
      | OPRF password mapping | "2FApi-OPRF-HashToGroup-v1" |
      | Sigma challenge | "2FApi-v1.0-Sigma" |
    And no cross-protocol attack is possible

  # --- Error Cases ---

  Scenario: Proof of possession included in enrollment commitment
    Given Alice registers commitment C during enrollment
    When the SDK sends C to the server
    Then the SDK also sends a proof-of-possession (Sigma proof that client knows s, r opening C)
    And the server verifies the proof before accepting C
    And a random point cannot be registered as a commitment (must prove knowledge)

  Scenario: Supply chain attack on WASM binary detected via SRI
    Given an attacker compromised the npm package @2fapi/crypto-wasm
    When the SDK loads the WASM binary
    Then the Subresource Integrity hash does not match the expected value
    And the SDK refuses to use the compromised binary
    And Alice sees "Security verification failed"
    And no cryptographic operations are performed with the compromised code

  Scenario: Extension DOM-scrapes passphrase fields
    Given a malicious extension reads the DOM input values
    When Alice types her passphrase in the input fields
    Then the extension can read the passphrase from the DOM (accepted risk)
    And MITIGATION: the passphrase alone is insufficient (OPRF + hardware still needed)
    And MITIGATION: the vault_key requires all 3 factors, passphrase is just one
    And this is documented: "passphrase input exposure to hostile browser is mitigated by multi-factor vault key"
