# Prioritized BDD Scenarios — OPRF + Hardware-Bound Vault

> Prioritized on 2026-03-26
> Source: docs/bdd/oprf-hardware-vault-scenarios.md

## Priority Summary

| Priority | Count | Est. TDD Cycles | Cumulative Cycles |
|----------|-------|-----------------|-------------------|
| P1       | 14    | ~20             | ~20               |
| P2       | 17    | ~35             | ~55               |
| **MVP**  | **31**| **~55**         | **~55**           |
| P3       | 10    | ~25             | ~80               |
| P4       | 2     | ~6              | ~86               |
| **Total**| **43**| **~86**         | **~86**           |

## Simplification Log

| Action | Original | Result | Reason |
|--------|----------|--------|--------|
| SPLIT | #1 Successful OPRF derivation (8 steps) | #1a Client blinding, #1b Server eval + unblind | Too many steps |
| MERGE | #2 Deterministic + #3 Different passwords | Scenario Outline "OPRF determinism" | Redundant variations |
| MERGE | #8 Invalid point + #9 Identity point | Scenario Outline "Invalid server response" | Same validation, variants |
| MERGE | #26 Eve no HW + #27 Eve no OPRF + #28 Eve no password | Scenario Outline "Eve missing one factor" | 3 variants of same test |
| MERGE | #30 OPRF OK/PRF fail + #31 PRF OK/OPRF fail | "Partial factor failure" | Symmetric error handling |
| REMOVE | #15 Same credential same hw_key | Covered by #2 determinism | Redundant |
| REWRITE | #11 MITM modifies B | "GCM tag mismatch indistinguishable from wrong password" | More precise |

## Dependency Graph

```
FOUNDATION (P1):
  #47 (domain separation) ──┐
  #48 (proof of possession) ├──► #35 (server gen OPRF key)
                             │         │
  #41 (validate blinded pt) ─┤         ▼
  #42 (OPRF key not found)  ─┤   #36 (server evaluate)
  #40 (eval refused if wipe) ┤         │
  #37 (check counter first) ─┘         ▼
                               #1a (client blind)
  #8+9 (invalid eval resp) ──►  #1b (unblind + HKDF)
  #4 (blinding ZK property) ─►       │
  #5 (fresh r anti-replay) ──►       │
  #2+3 (determinism) ────────►       │
  #12 (server offline) ─────►        │
  #27 (offline = impossible) ►       │
                                     ▼
MVP (P2):                     #25 (unseal Tier 1a)
  #10 (r=0), #11 (MITM)              │
  #32 (wrong pwd), #33 (wipe)        ▼
  #34 (concurrent)           #16 (fallback Tier 1a)
  #6 (perf), #43, #44, #45  #19 (bio fail → Tier 0)
  #26+28 (Eve), #18, #38    #30+31 (partial fail)

POST-MVP (P3):
  #13 (HW seal) ──► #14 (HW unseal) ──► #23+24 (3-factor)
  #17, #20, #21, #22, #29, #39, #50

POST-MVP (P4):
  #46 (version), #49 (SRI)
```

---

## Scenario #47 — [P1] Hash-to-curve domain separation

**Feature**: Protocol Integrity
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — prevents cross-protocol attacks between OPRF and Sigma
**Cost**: LOW — single constant definition
**Dependencies**: none (foundation stone)
**Est. TDD cycles**: 1

```gherkin
Feature: Domain separation between OPRF and Sigma protocols

  Scenario: Hash-to-curve uses distinct domain separation tags per protocol
    Given the OPRF uses hash_to_curve for password mapping
    And the Sigma protocol uses hash_to_curve for challenge derivation
    When both use SHA-512 internally
    Then the domain separation tags are different:
      | Context              | DST                            |
      | OPRF password mapping | "2FApi-OPRF-HashToGroup-v1"   |
      | Sigma challenge       | "2FApi-v1.0-Sigma"            |
    And no cross-protocol attack is possible
```

---

## Scenario #48 — [P1] Proof of possession in enrollment

**Feature**: Protocol Integrity
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — prevents rogue commitment registration
**Cost**: LOW — already implemented server-side, need to verify in flow
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: Enrollment requires proof of knowledge of commitment opening

  Scenario: Commitment registration includes proof-of-possession
    Given Alice registers commitment C during enrollment
    When the SDK sends C to the server
    Then the SDK also sends a proof-of-possession (Sigma proof that client knows s, r opening C)
    And the server verifies the proof before accepting C
    And a random point cannot be registered as a commitment (must prove knowledge)
```

---

## Scenario #41 — [P1] Invalid blinded point rejected

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — input validation prevents crashes and oracle attacks
**Cost**: LOW — is_canonical check on Ristretto point
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: Server validates blinded points before evaluation

  Scenario: Non-canonical or identity blinded point is rejected
    Given Eve sends a non-canonical or identity point as B
    When the server validates B
    Then the server rejects with "invalid blinded element"
    And no evaluation is performed
    And the attempt counter is NOT incremented (malformed request, not a password attempt)
```

---

## Scenario #42 — [P1] OPRF key not found

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — basic error handling for non-existent vault
**Cost**: LOW — null check + 404
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: Server handles missing OPRF keys

  Scenario: OPRF evaluation request for non-existent vault returns 404
    Given Dave has no vault on this device
    When Dave sends an OPRF evaluation request
    Then the server responds with 404 "no vault registered for this device"
```

---

## Scenario #40 — [P1] OPRF evaluation refused after wipe

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — wipe must be permanent and enforced
**Cost**: LOW — check is_wiped flag
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: Wiped vaults cannot be unsealed

  Scenario: OPRF evaluation permanently refused after wipe
    Given the attempt counter triggered a wipe
    When Eve sends an OPRF evaluation request
    Then the server responds { status: "wiped" }
    And the OPRF key has been permanently deleted
    And no evaluation is performed
```

---

## Scenario #37 — [P1] OPRF evaluation checks counter first

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — counter must gate evaluation to prevent unlimited attempts
**Cost**: LOW — check before evaluate
**Dependencies**: #40 (wipe logic)
**Est. TDD cycles**: 1

```gherkin
Feature: Attempt counter gates OPRF evaluation

  Scenario: Server checks attempt counter before evaluating OPRF
    Given Alice has 2 failures on this device
    When Alice sends a new OPRF evaluation request
    Then the server checks the attempt counter (2 < 3 threshold)
    And the server evaluates E = k · B
    And responds with { evaluated: E, attempts_remaining: 1 }
```

---

## Scenario #35 — [P1] Server generates OPRF key during seal

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — prerequisite for all OPRF operations
**Cost**: MEDIUM — new domain model + DB table + route
**Dependencies**: #41, #42, #40, #37 (validation + counter)
**Est. TDD cycles**: 3

```gherkin
Feature: OPRF key generation during vault seal

  Scenario: Server generates and stores OPRF key
    Given Alice requests a vault seal
    When the server receives POST /v1/vault/seal
    Then the server generates a random 256-bit scalar k (the OPRF key)
    And stores k in the database per (client_id, device_id)
    And responds with status "ready" (NOT the key — client never sees k)
    And the client proceeds to the OPRF evaluation step
```

---

## Scenario #36 — [P1] Server evaluates OPRF blindly

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — core server operation
**Cost**: MEDIUM — scalar multiplication + route + audit log
**Dependencies**: #35 (key must exist)
**Est. TDD cycles**: 3

```gherkin
Feature: Blind OPRF evaluation

  Scenario: Server evaluates blinded point without learning password
    Given Alice sends blinded point B to POST /v1/vault/oprf-evaluate
    And the server retrieves OPRF key k for (client_id, device_id)
    When the server computes E = k · B
    Then the server returns E (32 bytes, compressed Ristretto point)
    And the server logs: "oprf_evaluation: client_id, device_id, timestamp"
    And the server does NOT log B or E (they are ephemeral)
```

---

## Scenario #1a — [P1] Client blinding

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — client side of OPRF protocol
**Cost**: MEDIUM — hash_to_curve + scalar mult in Rust/WASM
**Dependencies**: #47 (domain separation tag)
**Est. TDD cycles**: 3

```gherkin
Feature: Client-side OPRF blinding

  Scenario: SDK blinds the password before sending to server
    Given Alice enters her device password "MyD3v!ceP@ss"
    When the SDK computes P = hash_to_curve("MyD3v!ceP@ss")
    And the SDK generates a random blinding factor r
    And the SDK computes B = r · P (blinded point)
    Then B is a valid Ristretto255 point
    And B reveals nothing about "MyD3v!ceP@ss" (random-looking)
    And the SDK sends B to the server
```

---

## Scenario #1b — [P1] Server eval + client unblind

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — completes OPRF round-trip, produces vault key
**Cost**: MEDIUM — unblinding + HKDF
**Dependencies**: #1a (blinding), #36 (server eval)
**Est. TDD cycles**: 3

```gherkin
Feature: Client-side OPRF unblinding and key derivation

  Scenario: SDK unblinds server response and derives vault key
    Given the server returned evaluated point E
    When the SDK computes U = r⁻¹ · E (unblinds)
    Then U = k · P = OPRF(k, password) and is deterministic for same password
    And the SDK derives vault_key = HKDF(U, device_id, "2fapi-vault-seal-v1")
    And the password never left the client (not even as a hash)
    And the OPRF key k never left the server
    And U is zeroized after HKDF
```

---

## Scenario #4 — [P1] Blinding ZK property

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — mathematical guarantee of zero-knowledge
**Cost**: LOW — property test
**Dependencies**: #1a (blinding implementation)
**Est. TDD cycles**: 1

```gherkin
Feature: Zero-knowledge property of OPRF blinding

  Scenario: Blinding factor prevents server from learning password
    Given Alice sends blinded point B to the server
    When the server observes B
    Then B = r · hash_to_curve(password) where r is random
    And without r, the server cannot recover hash_to_curve(password)
    And the server cannot perform a dictionary attack against B
    And this holds under the Decisional Diffie-Hellman assumption on Ristretto255
```

---

## Scenario #5 — [P1] Fresh blinding prevents replay

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — replay resistance is non-negotiable
**Cost**: LOW — test with two different r values
**Dependencies**: #1b (unblinding)
**Est. TDD cycles**: 1

```gherkin
Feature: Replay resistance via fresh blinding

  Scenario: Replayed server response produces wrong vault key
    Given Eve intercepted a previous OPRF response E₁ (from blinding r₁)
    When Alice performs a new OPRF with fresh blinding r₂
    And Eve replays E₁ instead of the real E₂
    Then Alice unblinds: r₂⁻¹ · E₁ ≠ r₁⁻¹ · E₁ = U
    And the wrong vault key is derived
    And AES-GCM decryption fails (tag mismatch)
    And Alice sees "Wrong password" (indistinguishable from actual wrong password)
```

---

## Scenario #2+3 — [P1] OPRF determinism

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — vault must reopen with same password, reject different password
**Cost**: LOW — property test
**Dependencies**: #1b (full OPRF round-trip)
**Est. TDD cycles**: 1

```gherkin
Feature: OPRF output determinism

  Scenario Outline: OPRF produces consistent output per password
    Given Alice uses password <password> on <attempt_count> separate logins
    When the SDK performs the OPRF protocol each time (with fresh random blinding)
    Then all unblindings produce the same U = k · hash_to_curve(<password>)
    And <vault_result>

    Examples:
      | password       | attempt_count | vault_result                              |
      | "MyD3v!ceP@ss" | 2             | the same vault key is derived both times  |
      | "WrongP@ss!"   | 1             | a different vault key is derived           |
      |                 |               | and AES-GCM decryption fails (tag mismatch)|
```

---

## Scenario #8+9 — [P1] Invalid server response validation

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — reject malicious/buggy server responses
**Cost**: LOW — point validation
**Dependencies**: #1b (unblinding step)
**Est. TDD cycles**: 1

```gherkin
Feature: Server response validation

  Scenario Outline: SDK rejects invalid evaluated points from server
    Given the server returns <invalid_response> as evaluated point E
    When the SDK validates E before unblinding
    Then the SDK rejects with <error_message>
    And the unseal attempt is aborted
    And no partial key derivation occurs

    Examples:
      | invalid_response       | error_message                                |
      | non-canonical bytes    | "Server returned invalid data. Please try again." |
      | identity element (k=0) | "OPRF evaluation produced identity element"  |
```

---

## Scenario #12 — [P1] Server unreachable fallback

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: CRITICAL — offline must have a graceful fallback
**Cost**: LOW — error handling
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: Offline fallback when server unreachable

  Scenario: OPRF cannot proceed without server — fallback to passphrase
    Given Alice's device has no network connection
    When the SDK cannot send B to the server
    Then the OPRF cannot proceed (server evaluation is required)
    And Alice sees "Server required. Use passphrase instead."
    And Alice falls back to Tier 0 (direct Argon2id derivation)
```

---

## Scenario #27 — [P1] Offline brute-force impossible

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — THE founding question ("what stops offline cracking?")
**Cost**: LOW — attack test
**Dependencies**: #1b (OPRF implemented)
**Est. TDD cycles**: 1

```gherkin
Feature: Offline brute-force resistance

  Scenario: Stolen device with known password cannot unseal offline
    Given Eve stole Alice's laptop (has hardware) and knows the password
    When Eve tries to unseal offline
    Then Eve can derive hw_key (has the hardware + biometric bypass)
    But Eve is missing the OPRF output U (requires server evaluation)
    And without network access, U cannot be obtained
    And the vault is indecryptable offline
```

---

## --- MVP CUT LINE ---

---

## Scenario #25 — [P2] Unseal with 2 factors (Tier 1a)

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — main path for devices without hardware PRF
**Cost**: MEDIUM — full unseal orchestration
**Dependencies**: #1b, #35, #36 (OPRF infrastructure)
**Est. TDD cycles**: 3

```gherkin
Feature: Two-factor vault unseal (Tier 1a)

  Scenario: Unseal vault with password + OPRF (no hardware key)
    Given Bob's device has no PRF support
    And Bob's vault was sealed with 2 factors (password + OPRF)
    When Bob enters his password
    And the OPRF completes
    Then vault_key = HKDF(U, device_id) — 2-factor
    And the vault decrypts successfully
    And Bob is authenticated
```

---

## Scenario #32 — [P2] Wrong password detection

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — UX feedback + counter increment
**Cost**: MEDIUM — orchestrate OPRF + GCM failure + counter
**Dependencies**: #25 (unseal flow)
**Est. TDD cycles**: 2

```gherkin
Feature: Wrong password detection via OPRF

  Scenario: Wrong password produces wrong OPRF output and GCM failure
    Given Eve enters the wrong password
    When the SDK computes B = r · hash_to_curve(wrong_password)
    And the server evaluates E = k · B
    And the SDK unblinds: U_wrong = r⁻¹ · E
    Then U_wrong ≠ U_correct (different password → different OPRF output)
    And vault_key is wrong
    And AES-GCM decryption fails (tag mismatch)
    And the server increments the failure counter
    And Eve sees "Wrong password. N attempts remaining."
```

---

## Scenario #33 — [P2] Three failures → OPRF key destroyed

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — permanent wipe on brute-force
**Cost**: MEDIUM — counter + key deletion
**Dependencies**: #32 (wrong password increments counter)
**Est. TDD cycles**: 2

```gherkin
Feature: Permanent vault wipe after threshold

  Scenario: Three failed unseal attempts destroy the OPRF key permanently
    Given the failure counter reached 3
    When the server triggers a wipe
    Then the OPRF key k is permanently deleted
    And even with the correct password + hardware, the vault is undecryptable
    And Alice must re-enroll via passphrase and re-seal the vault
```

---

## Scenario #34 — [P2] Concurrent evaluations serialized

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — race condition = security bypass
**Cost**: MEDIUM — atomic counter increment
**Dependencies**: #32, #33 (counter logic)
**Est. TDD cycles**: 2

```gherkin
Feature: Concurrent evaluation serialization

  Scenario: Simultaneous OPRF evaluations are serialized by the server
    Given Eve submits two blind evaluations simultaneously
    When the server receives both
    Then the server serializes them (atomic counter increment)
    And each evaluation increments the counter independently
    And no race condition allows extra attempts
```

---

## Scenario #10 — [P2] Blinding factor r = 0

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: IMPORTANT — rare but fatal edge case
**Cost**: LOW — identity check + retry
**Dependencies**: #1a (blinding)
**Est. TDD cycles**: 1

```gherkin
Feature: Degenerate blinding factor handling

  Scenario: Blinding factor zero is detected and retried
    Given a random number generator produces r = 0
    When the SDK computes B = 0 · P = identity
    Then the SDK detects B is the identity point
    And the SDK regenerates r and retries (transparent to user)
    And the degenerate case never reaches the server
```

---

## Scenario #11 — [P2] MITM indistinguishable from wrong password

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: IMPORTANT — MITM fails silently (good security property)
**Cost**: LOW — already covered by GCM design
**Dependencies**: #1b (unblinding)
**Est. TDD cycles**: 1

```gherkin
Feature: MITM attack detection

  Scenario: Modified blinded point produces GCM failure indistinguishable from wrong password
    Given Mallory intercepts and modifies B in transit
    When the server evaluates E = k · B' (modified point)
    And the SDK unblinds with the original r
    Then the result is garbage (not OPRF(k, password))
    And AES-GCM decryption fails (tag mismatch)
    And Alice sees "Wrong password" (MITM is indistinguishable from wrong password)
```

---

## Scenario #6 — [P2] OPRF performance

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: IMPORTANT — UX benchmark
**Cost**: LOW — timing assertion
**Dependencies**: #1a, #1b, #36 (full round-trip)
**Est. TDD cycles**: 1

```gherkin
Feature: OPRF performance

  Scenario: OPRF evaluation completes in under 5ms total crypto time
    Given the OPRF requires one scalar multiplication on each side
    When the SDK computes blinding and unblinding in WASM
    And the server computes the evaluation
    Then the client-side crypto takes < 2ms
    And the server-side crypto takes < 1ms
    And the total OPRF overhead is dominated by network latency, not crypto
```

---

## Scenario #16 — [P2] PRF unavailable → fallback Tier 1a

**Feature**: Hardware-Bound Key
**Bounded Context**: Hardware-Bound Key
**Value**: CRITICAL — main fallback path
**Cost**: MEDIUM — detection + branching
**Dependencies**: #25 (Tier 1a unseal)
**Est. TDD cycles**: 2

```gherkin
Feature: Tier 1a fallback when hardware PRF unavailable

  Scenario: Device without PRF extension falls back to 2-factor vault
    Given Bob's device supports WebAuthn but NOT the PRF extension
    When the SDK checks for PRF support during seal
    Then the SDK skips the hardware key factor
    And vault_key = HKDF(U, device_id) — 2-factor (password + OPRF)
    And Bob is informed: "Your device does not support hardware binding. Vault is protected by password + server."
```

---

## Scenario #18 — [P2] PRF requires user verification

**Feature**: Hardware-Bound Key
**Bounded Context**: Hardware-Bound Key
**Value**: CRITICAL — prevents silent hw_key extraction
**Cost**: LOW — config flag
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: WebAuthn PRF user verification requirement

  Scenario: PRF requires biometric or PIN each time
    Given Alice tries to derive the hardware key
    When the SDK calls credentials.get() with userVerification: "required"
    Then Alice must touch her fingerprint sensor (no silent access)
    And the PRF is only evaluated after biometric confirmation
    And a malicious script cannot silently extract hw_key
```

---

## Scenario #19 — [P2] Biometric fails → Tier 0

**Feature**: Hardware-Bound Key
**Bounded Context**: Hardware-Bound Key
**Value**: CRITICAL — fallback cascade must work
**Cost**: MEDIUM — orchestration
**Dependencies**: #16 (Tier 1a fallback concept)
**Est. TDD cycles**: 2

```gherkin
Feature: Biometric failure cascade to Tier 0

  Scenario: Biometric failure prevents PRF, user falls back to passphrase
    Given Alice's fingerprint is not recognized 3 times
    When the WebAuthn prompt times out
    Then the SDK cannot derive hw_key
    And the vault cannot be decrypted (missing hardware factor)
    And Alice falls back to Tier 0 (type passphrase, Argon2id derivation)
```

---

## Scenario #30+31 — [P2] Partial factor failure

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — zeroize immediately on partial failure
**Cost**: MEDIUM — state management
**Dependencies**: #25 (unseal flow)
**Est. TDD cycles**: 2

```gherkin
Feature: Partial factor failure handling

  Scenario Outline: One factor succeeds but the other fails — zeroize and fallback
    Given <first_factor> completed successfully
    When <second_factor> fails
    Then the result of <first_factor> is zeroized immediately
    And Alice sees <message>
    And Alice falls back to Tier 0 (passphrase)

    Examples:
      | first_factor          | second_factor             | message                                  |
      | OPRF evaluation (U)   | WebAuthn PRF (hw_key)     | "Biometric failed. Use passphrase."      |
      | WebAuthn PRF (hw_key) | OPRF server unreachable   | "Server required for vault unlock."      |
```

---

## Scenario #26+28 — [P2] Eve missing one factor

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: IMPORTANT — security proofs
**Cost**: LOW — attack tests
**Dependencies**: #25 (unseal flow)
**Est. TDD cycles**: 2

```gherkin
Feature: Multi-factor security proof

  Scenario Outline: Attacker with two factors cannot unseal vault
    Given Eve has <factor_1> and <factor_2>
    But Eve is missing <missing_factor>
    When Eve attempts to derive the vault key
    Then Eve cannot compute vault_key = HKDF(U || hw_key)
    And the vault is indecryptable

    Examples:
      | factor_1        | factor_2          | missing_factor           |
      | password + OPRF | —                 | hardware key (Tier 1b)   |
      | server OPRF key | hardware          | password                 |
```

---

## Scenario #38 — [P2] OPRF key rotation on re-seal

**Feature**: OPRF Server-Side Management
**Bounded Context**: OPRF Server-Side Management
**Value**: IMPORTANT — clean re-seal
**Cost**: LOW — delete + insert
**Dependencies**: #35 (server generates key)
**Est. TDD cycles**: 1

```gherkin
Feature: OPRF key rotation

  Scenario: Server generates fresh OPRF key on vault re-seal
    Given Alice re-seals her vault (new password)
    When the server receives a new seal request
    Then the server generates a fresh OPRF key k'
    And replaces the old key k
    And resets the attempt counter to 0
```

---

## Scenario #43 — [P2] OPRF correctness (property test)

**Feature**: Protocol Integrity
**Bounded Context**: Protocol Integrity
**Value**: CRITICAL — mathematical proof of correctness
**Cost**: MEDIUM — property-based test infrastructure
**Dependencies**: #1a, #1b (full OPRF)
**Est. TDD cycles**: 2

```gherkin
Feature: OPRF algebraic correctness

  Scenario: Property test — blind/evaluate/unblind cycle always produces correct result
    Given Alice uses password P and the server has OPRF key k
    When Alice performs N OPRF evaluations with different blinding factors r₁...rₙ
    Then all N unblindings produce the same U = k · hash_to_curve(P)
    And this is verified: ∀r, unblind(evaluate(blind(P, r), k), r) = k · H(P)
    And tested with fast-check, 10000 iterations
```

---

## Scenario #44 — [P2] OPRF obliviousness (property test)

**Feature**: Protocol Integrity
**Bounded Context**: Protocol Integrity
**Value**: CRITICAL — mathematical proof of zero-knowledge
**Cost**: MEDIUM — statistical test
**Dependencies**: #1a (blinding)
**Est. TDD cycles**: 2

```gherkin
Feature: OPRF statistical obliviousness

  Scenario: Property test — blinded points are indistinguishable from random
    Given the server sees blinded point B = r · H(password)
    Then B is uniformly random on the Ristretto255 group (for random r)
    And no polynomial-time algorithm can distinguish B from a random point
    And a property-based test verifies: ∀p₁,p₂, distribution of blind(p₁,r) ≈ blind(p₂,r)
```

---

## Scenario #45 — [P2] Non-malleability

**Feature**: Protocol Integrity
**Bounded Context**: Protocol Integrity
**Value**: IMPORTANT — unforgeability of proofs
**Cost**: LOW — bit flip test
**Dependencies**: none (tests existing Sigma proofs)
**Est. TDD cycles**: 1

```gherkin
Feature: Proof non-malleability

  Scenario: Modified proof is rejected by server
    Given Eve intercepts Alice's Sigma proof (96 bytes)
    When Eve flips a single bit in the proof
    Then the server's proof verification fails
    And the modified proof is indistinguishable from a random wrong proof
    And Eve cannot create a valid proof from a modified one (unforgeability under DLOG)
```

---

## --- POST-MVP (P3) ---

---

## Scenario #13 — [P3] Hardware key seal via WebAuthn PRF

**Feature**: Hardware-Bound Key
**Bounded Context**: Hardware-Bound Key
**Value**: CRITICAL — foundation of Tier 1b
**Cost**: HIGH — WebAuthn PRF integration
**Dependencies**: #1b (OPRF key derivation)
**Est. TDD cycles**: 4

```gherkin
Feature: Hardware-bound key derivation during seal

  Scenario: SDK derives hardware key via WebAuthn PRF during vault seal
    Given Alice is sealing her vault
    When the SDK creates a WebAuthn credential with the PRF extension
    And Alice confirms with her fingerprint
    Then the SDK receives hw_key = PRF(credential, "2fapi-vault-hw-v1")
    And hw_key is 256 bits, derived inside the secure element
    And hw_key is combined with OPRF output: vault_key = HKDF(U || hw_key)
    And the vault is encrypted with vault_key
```

---

## Scenario #14 — [P3] Hardware key unseal via WebAuthn PRF

**Feature**: Hardware-Bound Key
**Bounded Context**: Hardware-Bound Key
**Value**: CRITICAL — counterpart to seal
**Cost**: MEDIUM — same API, different direction
**Dependencies**: #13 (seal must exist first)
**Est. TDD cycles**: 2

```gherkin
Feature: Hardware-bound key retrieval during unseal

  Scenario: SDK retrieves hardware key via WebAuthn PRF during unseal
    Given Alice is unsealing her vault
    And the OPRF output U was computed
    When the SDK calls navigator.credentials.get() with PRF extension
    And Alice touches her fingerprint sensor
    Then the same hw_key is derived (deterministic PRF)
    And vault_key = HKDF(U || hw_key) matches the seal-time key
    And the vault decrypts successfully
```

---

## Scenario #23 — [P3] Seal vault with 3 factors

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — full 3-factor seal flow
**Cost**: HIGH — orchestrates OPRF + PRF + AES-GCM
**Dependencies**: #1b, #13 (OPRF + HW key)
**Est. TDD cycles**: 4

```gherkin
Feature: Three-factor vault sealing

  Scenario: Vault sealed with password + OPRF + hardware key
    Given Alice completed enrollment and derived her secret
    When Alice chooses "Device password" at the protection step
    And Alice types password "MyD3v!ceP@ss"
    Then the SDK performs OPRF: blind → server evaluate → unblind → U
    And the SDK derives hw_key via WebAuthn PRF (fingerprint confirm)
    And the SDK derives vault_key = HKDF(U || hw_key, device_id)
    And the SDK encrypts (secret, blinding) with AES-256-GCM using vault_key
    And the vault is stored in localStorage
    And password, U, hw_key, and vault_key are all zeroized
```

---

## Scenario #24 — [P3] Unseal vault with 3 factors

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: CRITICAL — full 3-factor unseal flow
**Cost**: HIGH — orchestrates OPRF + PRF + decrypt
**Dependencies**: #23 (seal must exist)
**Est. TDD cycles**: 4

```gherkin
Feature: Three-factor vault unsealing

  Scenario: Vault unsealed with password + OPRF + hardware key
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
```

---

## Scenario #29 — [P3] Vault downgrade 3-factor → 2-factor

**Feature**: Combined 3-Factor Vault
**Bounded Context**: Combined 3-Factor Vault
**Value**: IMPORTANT — graceful migration
**Cost**: MEDIUM — orchestration
**Dependencies**: #24 (3-factor unseal), #25 (2-factor unseal)
**Est. TDD cycles**: 2

```gherkin
Feature: Vault tier downgrade

  Scenario: Hardware PRF failure forces downgrade from Tier 1b to Tier 1a
    Given Alice's hardware stopped supporting PRF (OS update regression)
    When Alice tries to unseal and PRF fails
    Then Alice falls back to Tier 0 (passphrase)
    And after successful auth, Alice is offered to re-seal at Tier 1a (2-factor)
    And the old 3-factor vault is deleted (undecryptable without PRF)
```

---

## Scenario #7 — [P3] OPRF inside WASM boundary

**Feature**: OPRF Key Derivation
**Bounded Context**: OPRF Key Derivation
**Value**: IMPORTANT — defense-in-depth against hostile browser
**Cost**: HIGH — WASM boundary architecture
**Dependencies**: #1a, #1b (OPRF client-side)
**Est. TDD cycles**: 4

```gherkin
Feature: WASM memory isolation for OPRF

  Scenario: OPRF intermediate values never cross WASM↔JS boundary
    Given the SDK performs the OPRF protocol
    When the blinding, hash_to_curve, and unblinding are computed
    Then all scalar operations (r, r⁻¹, P, B, U) are in WASM linear memory
    And only the blinded point B (32 bytes) crosses to JS for network
    And only the evaluated point E (32 bytes) crosses back
    And the unblinded result U is used directly in WASM for HKDF
    And U never crosses the WASM↔JS boundary
```

---

## Scenario #17 — [P3] HW key changes after credential re-creation

**Feature**: Hardware-Bound Key
**Value**: IMPORTANT — credential rotation
**Cost**: LOW — property test
**Dependencies**: #13
**Est. TDD cycles**: 1

```gherkin
Feature: Hardware key changes on credential rotation

  Scenario: New credential produces different hardware key
    Given Alice re-enrolled biometrics (new WebAuthn credential)
    When the SDK tries to unseal with the new credential
    Then the new PRF output is DIFFERENT from the old one
    And the old vault cannot be decrypted
    And Alice must re-seal the vault after authenticating via passphrase
```

---

## Scenario #20 — [P3] Secure element hardware failure

**Feature**: Hardware-Bound Key
**Value**: IMPORTANT — rare but must be handled
**Cost**: LOW — error handling
**Dependencies**: #14
**Est. TDD cycles**: 1

```gherkin
Feature: Hardware failure handling

  Scenario: TPM/Secure Enclave malfunction falls back to passphrase
    Given the TPM/Secure Enclave malfunctions
    When the SDK calls credentials.get() and receives an error
    Then Alice sees "Hardware security module error. Use passphrase instead."
    And the vault remains sealed (not deleted — hardware may recover)
    And Alice authenticates via Tier 0
```

---

## Scenario #21 — [P3] Extension intercept defense-in-depth

**Feature**: Hardware-Bound Key
**Value**: IMPORTANT — documents accepted risk
**Cost**: LOW — documentation + test
**Dependencies**: #14
**Est. TDD cycles**: 1

```gherkin
Feature: Extension interception mitigation

  Scenario: Malicious extension reads PRF output but cannot decrypt vault
    Given a malicious extension hooks navigator.credentials.get()
    When the extension reads clientExtensionResults (including hw_key)
    Then hw_key alone is insufficient (needs OPRF output U too)
    And U is inside WASM memory (never crosses to JS)
    And the attacker needs BOTH factors simultaneously — defense in depth
```

---

## Scenario #22 — [P3] Device clone → HW key not portable

**Feature**: Hardware-Bound Key
**Value**: IMPORTANT — TPM property
**Cost**: LOW — property test
**Dependencies**: #13
**Est. TDD cycles**: 1

```gherkin
Feature: Hardware binding prevents device cloning

  Scenario: Cloned device cannot derive hardware key
    Given Eve clones Alice's laptop disk
    When Eve boots the clone on different hardware
    Then the WebAuthn credential is bound to the ORIGINAL hardware's TPM
    And PRF evaluation fails on the clone
    And the vault is undecryptable on the cloned hardware
```

---

## Scenario #39 — [P3] OPRF key ≠ Pedersen commitment

**Feature**: OPRF Server-Side Management
**Value**: IMPORTANT — domain isolation proof
**Cost**: LOW — documentation test
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: OPRF and Pedersen key independence

  Scenario: OPRF key and Pedersen commitment serve different purposes
    Given Alice's Pedersen commitment C is stored for authentication
    And Alice's OPRF key k is stored for vault protection
    Then C and k are independent (different purposes)
    And compromising k does not help forge proofs (C is unrelated)
    And compromising C does not help decrypt the vault (k is unrelated)
```

---

## Scenario #50 — [P3] Extension DOM scrape accepted risk

**Feature**: Protocol Integrity
**Value**: IMPORTANT — documents threat model boundary
**Cost**: LOW — documentation
**Dependencies**: none
**Est. TDD cycles**: 1

```gherkin
Feature: Passphrase exposure risk documentation

  Scenario: Extension can read passphrase from DOM — mitigated by multi-factor
    Given a malicious extension reads the DOM input values
    When Alice types her passphrase in the input fields
    Then the extension can read the passphrase from the DOM (accepted risk)
    And MITIGATION: the passphrase alone is insufficient (OPRF + hardware still needed)
    And MITIGATION: vault_key requires all 3 factors, passphrase is just one
```

---

## --- POST-MVP (P4) ---

---

## Scenario #46 — [P4] Protocol version mismatch

**Feature**: Protocol Integrity
**Value**: IMPORTANT — forward compatibility
**Cost**: MEDIUM — version negotiation
**Dependencies**: none
**Est. TDD cycles**: 3

```gherkin
Feature: Protocol version negotiation

  Scenario: WASM v2 / Server v1 mismatch detected and reported
    Given the WASM module uses protocol v2 for the Fiat-Shamir transcript
    And the server expects protocol v1
    When Alice sends a proof computed with v2 transcript
    Then the server rejects: "unsupported protocol version"
    And Alice sees "Please update your app"
    And the SDK can negotiate the version via a header
```

---

## Scenario #49 — [P4] Supply chain SRI check

**Feature**: Protocol Integrity
**Value**: IMPORTANT — defense-in-depth
**Cost**: MEDIUM — SRI infrastructure
**Dependencies**: none
**Est. TDD cycles**: 3

```gherkin
Feature: WASM binary integrity verification

  Scenario: Compromised npm package detected via Subresource Integrity
    Given an attacker compromised the npm package @2fapi/crypto-wasm
    When the SDK loads the WASM binary
    Then the Subresource Integrity hash does not match the expected value
    And the SDK refuses to use the compromised binary
    And Alice sees "Security verification failed"
    And no cryptographic operations are performed with the compromised code
```
