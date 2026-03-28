# BDD Scenarios — WASM Crypto Module

> Generated on 2026-03-26 via BDD Workshop
> Source: CEO sprint directive — WASM build for Argon2id + Pedersen + Sigma in browser

## Summary

| Bounded Context | Features | Scenarios | Happy | Edge | Error |
|----------------|----------|-----------|-------|------|-------|
| Module Loading | 2 | 10 | 3 | 4 | 3 |
| Argon2id Derivation | 2 | 12 | 3 | 4 | 5 |
| Proof Generation | 2 | 8 | 2 | 3 | 3 |
| Memory Zeroization | 2 | 10 | 2 | 4 | 4 |
| Adversarial Browser | 2 | 12 | 1 | 4 | 7 |
| Expert Amendments | 1 | 5 | 3 | 1 | 1 |
| **Total** | **11** | **57** | **14** | **20** | **23** |

## Context

The 2FApi client SDK runs cryptographic operations in the browser via WebAssembly.
The Rust crypto core (Ristretto255 Pedersen + Sigma + Argon2id) is compiled to WASM
via wasm-pack + wasm-bindgen. The WASM module is the ONLY place where secret
material (scalars, blinding factors) is manipulated.

```
Rust crypto-core
  │
  ├── wasm-pack build ──► @2fapi/crypto-wasm (browser)
  │                         ├── derive_credential(passphrase, email, tenant) → (s, r)
  │                         ├── commit(s, r) → C
  │                         ├── prove(s, r, C, nonce, ...) → proof
  │                         └── zeroize_secrets() → wipe WASM linear memory
  │
  └── napi-rs build ──► @2fapi/crypto-native (Node.js, existing)
```

### Threat Model

The browser is considered POTENTIALLY HOSTILE:
- Malicious extensions may observe storage events, intercept network, read DOM
- Spectre-class attacks may read WASM linear memory from JS
- A compromised JS runtime may instrument WASM function calls
- The SDK MUST minimize the secret exposure window in memory
- The SDK MUST NOT rely on browser isolation for security guarantees

### Mitigation Strategy

| Threat | Mitigation |
|--------|-----------|
| Extension reads storage | Secrets never in localStorage/sessionStorage/IndexedDB (except Tier 1 encrypted vault) |
| Extension intercepts network | Secrets never sent over network (only proofs, which are public) |
| Spectre reads WASM memory | Minimize exposure window: derive → prove → zeroize in single synchronous WASM call |
| Compromised JS instruments calls | Secret bytes never cross WASM↔JS boundary; proof is computed entirely inside WASM |
| Timing side-channel | All scalar operations constant-time (subtle crate, no branching on secret data) |

## Actors

| Actor | Role | Goal |
|-------|------|------|
| Alice | User in modern browser (Chrome, Firefox, Safari) | Authenticate via WASM crypto |
| Bob | User on older mobile browser | Authenticate despite limited WASM memory |
| SDK | 2FApi client WASM module | Load, derive, prove, zeroize |
| Browser | WASM runtime host | Provide memory, execution, crypto APIs |
| Eve | Attacker with malicious browser extension | Extract secrets from WASM memory or JS runtime |

## Hypotheses

1. WASM module bundle size < 300 KB gzipped (guideline from Frontend/SDK Engineer)
2. Module loading timeout: 10 seconds, then error
3. Argon2id memory: 64 MB on desktop, 32 MB on mobile (adaptive via navigator.deviceMemory)
4. Argon2id derivation time: ≥ 500ms (security) and ≤ 3000ms (UX)
5. The WASM module exposes a SINGLE "derive_and_prove" entry point that keeps secrets inside WASM
6. Secret bytes (s, r) NEVER cross the WASM↔JS boundary — only the proof (public) is returned to JS
7. The WASM module is loaded lazily (not blocking initial page render)
8. Node.js environments use the napi-rs native module instead (auto-detected)
9. The browser is potentially hostile — extensions, Spectre, instrumented runtime are in threat model

---

## Module Loading

### Feature: Loading the WASM crypto module in the browser

  As the 2FApi client SDK
  I want to load the WASM crypto module lazily
  So that authentication pages render quickly and crypto is ready when needed

  Background:
    Given Alice navigates to a page using the 2FApi SDK

  # --- Happy Path ---

  Scenario: WASM module loads successfully on modern desktop browser
    Given Alice uses Chrome 120 on a desktop computer
    When the SDK initializes
    Then the WASM module is fetched asynchronously (not blocking page render)
    And the module loads in under 2 seconds
    And the SDK emits a "module initialized" event
    And the passphrase/PIN input is enabled for interaction

  Scenario: WASM module loads successfully on modern mobile browser
    Given Alice uses Safari 17 on an iPhone
    When the SDK initializes
    Then the WASM module loads successfully
    And the SDK detects navigator.deviceMemory and selects mobile Argon2id parameters
    And the module is ready for use

  Scenario: Node.js environment uses native module instead
    Given the SDK detects a Node.js runtime (no WebAssembly.instantiateStreaming)
    When the SDK initializes
    Then the SDK loads @2fapi/crypto-native (napi-rs) instead of WASM
    And the same CryptoEngine interface is exposed
    And Argon2id derivation uses native code (faster than WASM)

  # --- Edge Cases ---

  Scenario: WASM module is cached after first load
    Given Alice loaded the WASM module on a previous visit
    When Alice returns to the login page
    Then the WASM module is served from the browser's HTTP cache
    And initialization takes under 100ms
    And no additional network request is made

  Scenario: WASM module loading is retried on transient failure
    Given the WASM fetch fails on first attempt (network hiccup)
    When the SDK retries after 1 second
    And the second attempt succeeds
    Then the module loads normally
    And Alice is not aware of the retry (no error shown)

  Scenario: WASM module integrity is verified
    Given the SDK fetches the WASM binary
    When the binary is received
    Then the SDK verifies the Subresource Integrity hash (SRI)
    And if the hash does not match, the module is rejected
    And Alice sees "Security verification failed. Please reload."

  Scenario: Concurrent page loads share one WASM instance
    Given Alice opens two tabs of the application
    When both tabs initialize the SDK
    Then each tab loads its own WASM module instance (no SharedArrayBuffer)
    And secrets in one tab are isolated from the other

  # --- Error Cases ---

  Scenario: Browser does not support WebAssembly
    Given Alice uses a very old browser (IE 11, Opera Mini)
    When the SDK checks for WebAssembly support
    Then the SDK shows "This browser cannot perform secure authentication. Please use a modern browser."
    And no fallback to server-side derivation is attempted
    And the login form is disabled

  Scenario: WASM module loading times out
    Given the network is extremely slow
    When the WASM fetch exceeds 10 seconds
    Then the SDK shows "Loading secure module... Please check your connection."
    And Alice can retry manually
    And no partial module is used

  Scenario: WASM module is corrupted in transit
    Given the CDN serves a corrupted WASM binary
    When WebAssembly.instantiate fails with a CompileError
    Then the SDK shows "Security module could not load. Please reload."
    And no sensitive operation is attempted
    And the error is logged to the console (no secret data in the log)

---

## Argon2id Derivation

### Feature: Deriving secrets from passphrase or PIN via Argon2id in WASM

  As a user (Alice)
  I want the SDK to derive my secret from my passphrase securely
  So that the derivation is slow enough to resist brute-force but fast enough to feel responsive

  Background:
    Given the WASM crypto module is loaded and ready

  # --- Happy Path ---

  Scenario: Passphrase derivation on desktop browser
    Given Alice types her 4-word passphrase "blue tiger fast moon"
    When the SDK calls derive_credential in WASM with memory=64MB, iterations=3
    Then the derivation takes between 500ms and 3000ms
    And a progress indicator shows "Deriving secure key..."
    And the derived secret (s, r) remains inside WASM linear memory
    And the secret bytes are NOT returned to JavaScript

  Scenario: PIN derivation on desktop browser
    Given Bob types his 6-digit PIN "847291"
    When the SDK calls derive_credential in WASM
    Then the same Argon2id parameters are used (64MB, 3 iterations)
    And the derivation produces a different secret than a passphrase
    And the derivation time is comparable (~500ms–3000ms)

  Scenario: Derivation is deterministic across devices
    Given Alice types "blue tiger fast moon" on Device A
    And Alice types "blue tiger fast moon" on Device B
    When both devices run Argon2id with the same salt (email + tenant_id)
    Then both devices derive the same secret (s, r)
    And the same commitment C can be verified by the server

  # --- Edge Cases ---

  Scenario: Mobile browser uses reduced memory parameter
    Given Bob uses a phone with navigator.deviceMemory = 2 (2 GB RAM)
    When the SDK detects low memory
    Then the SDK uses Argon2id with memory=32MB (instead of 64MB)
    And derivation takes between 300ms and 2000ms
    And the derived secret is DIFFERENT from the 64MB derivation
    And the server stores separate commitments per memory parameter level

  Scenario: Derivation shows progress updates
    Given Alice's derivation takes 1200ms
    When derivation is in progress
    Then the SDK updates the progress indicator every 200ms
    And the "Sign in" button is disabled during derivation
    And Alice cannot submit a second request

  Scenario: Very slow device exceeds 3000ms target
    Given Charlie uses an old Android phone
    When Argon2id derivation takes 4500ms
    Then the derivation completes (no timeout kill)
    And a warning is logged for telemetry: "derivation_slow: 4500ms"
    And authentication proceeds normally

  Scenario: WASM memory allocation for Argon2id
    Given the SDK requests 64MB of WASM linear memory for Argon2id
    When the browser allocates the memory
    Then the allocation is a single contiguous block (WebAssembly.Memory grow)
    And the SDK does not use JavaScript ArrayBuffer for the derivation
    And the 64MB is released (zeroized) after derivation completes

  # --- Error Cases ---

  Scenario: Argon2id out of memory on constrained device
    Given the device has very limited memory
    When the SDK attempts Argon2id with memory=64MB and allocation fails
    Then the SDK retries with memory=32MB
    And if 32MB also fails, the SDK shows "This device cannot perform secure key derivation"
    And the login form is disabled
    And no partial derivation result leaks

  Scenario: User navigates away during derivation
    Given Alice started typing her passphrase and derivation began
    When Alice navigates to a different page
    Then the WASM execution is terminated (page unload)
    And the WASM linear memory is freed by the browser
    And no secret material persists in any cache

  Scenario: Browser tab crashes during derivation
    Given Argon2id is consuming 64MB of WASM memory
    When the browser tab runs out of memory and crashes
    Then the WASM memory is released by the OS
    And no crash report contains the derived secret bytes
    And the crash dump does not include WASM linear memory content (browser policy)

  Scenario: Second derivation before first completes
    Given Alice submitted her passphrase and derivation is in progress
    When Alice somehow submits again (race condition)
    Then the SDK ignores the second submission (debounced)
    And only one derivation runs at a time
    And the first derivation completes normally

  Scenario: WASM thread hangs during derivation
    Given the WASM derivation does not return after 30 seconds
    When the SDK's watchdog timer fires
    Then the SDK terminates the WASM instance
    And Alice sees "Derivation timed out. Please try again."
    And a fresh WASM module is loaded for the next attempt

---

## Proof Generation

### Feature: Generating Sigma proofs entirely inside WASM

  As the 2FApi client SDK
  I want to compute Sigma proofs inside WASM without exposing secrets to JavaScript
  So that even a compromised browser cannot directly read the secret scalars

  Background:
    Given the WASM module is loaded and the secret was derived via Argon2id

  # --- Happy Path ---

  Scenario: Proof generated inside WASM without secret crossing the boundary
    Given Alice's secret (s, r) was derived and remains in WASM linear memory
    And the SDK received a challenge nonce from the server
    When the SDK calls prove_and_zeroize(nonce, channelBinding, clientId)
    Then the WASM module computes the Sigma proof internally
    And only the proof bytes (announcement + responses) are returned to JavaScript
    And the proof is public data (safe to expose to JS)
    And the secret (s, r) is zeroized inside WASM before the function returns

  Scenario: Proof is non-interactive (Fiat-Shamir)
    Given the WASM module has the secret, commitment, and nonce
    When it computes the challenge via Fiat-Shamir transform
    Then the challenge is c = SHA-512(tag || G || H || C || A || clientId || nonce || channelBinding)
    And the proof is (A, z_s, z_r) where z_s = k_s + c·s, z_r = k_r + c·r
    And the proof bytes match the server's expected format (96 bytes)

  # --- Edge Cases ---

  Scenario: Proof generation is fast (< 5ms)
    Given the secret is already derived in WASM memory
    When the SDK calls the proof generation function
    Then proof computation takes less than 5 milliseconds
    And no progress indicator is shown for the proof step

  Scenario: Challenge nonce is bound into the proof
    Given the server issued nonce N1
    When the SDK generates a proof with N1
    Then the proof is ONLY valid for N1
    And reusing the proof with a different nonce N2 is rejected by the server
    And the nonce prevents replay attacks

  Scenario: Channel binding included in transcript
    Given Alice is on https://app.acme.com
    When the SDK computes the Fiat-Shamir transcript
    Then the channel binding (origin or TLS binding) is included
    And a MITM who replays the proof on a different origin is detected

  # --- Error Cases ---

  Scenario: Proof generation with corrupted WASM memory
    Given a memory corruption occurred in WASM linear memory
    When the SDK attempts to generate a proof
    Then the WASM module detects the inconsistency (scalar not canonical)
    And returns an error instead of a malformed proof
    And the secret is zeroized regardless of the error

  Scenario: Proof generation after secret was already zeroized
    Given the secret was zeroized (e.g., timeout or previous proof)
    When the SDK attempts a second proof generation
    Then the WASM module returns an error "no secret in memory"
    And Alice is asked to re-enter her passphrase

  Scenario: Randomness failure during proof generation
    Given the WASM module needs random nonces (k_s, k_r) for the announcement
    When the browser's crypto.getRandomValues fails
    Then the proof generation is aborted
    And no deterministic fallback is used (this would be insecure)
    And Alice sees "Secure randomness unavailable. Please try again."

---

## Memory Zeroization

### Feature: Ensuring WASM linear memory is zeroized after secret use

  As the 2FApi security model
  I want all secret material overwritten with zeros in WASM memory after use
  So that the exposure window for side-channel attacks is minimized

  # --- Happy Path ---

  Scenario: Secret zeroized after proof generation
    Given Alice's secret (s, r) was derived and a proof was generated
    When the prove_and_zeroize function returns
    Then the 64 bytes of secret material (s=32, r=32) are overwritten with 0x00
    And the Argon2id intermediate state (64MB) is also zeroized
    And only the proof bytes (public) remain accessible

  Scenario: Blinding randomness also zeroized
    Given the proof generation created random nonces k_s and k_r
    When the proof is complete
    Then k_s and k_r are overwritten with zeros in WASM memory
    And only the computed responses z_s and z_r (public, part of proof) survive

  # --- Edge Cases ---

  Scenario: Zeroization happens even on error
    Given the SDK derived a secret successfully
    When an error occurs during proof computation (e.g., invalid nonce format)
    Then the secret is zeroized BEFORE the error propagates to JavaScript
    And the JavaScript error handler receives no secret material
    And the error message contains no byte values

  Scenario: Page navigation triggers zeroization
    Given Alice is authenticated and the SDK holds no more secrets
    When Alice navigates away from the page
    Then the beforeunload handler calls the WASM zeroize function
    And the entire WASM linear memory is overwritten
    And the WASM instance is dereferenced for garbage collection

  Scenario: Zeroization uses volatile writes (not optimized away)
    Given the Rust code uses `zeroize` crate for memory clearing
    When the WASM compiler (wasm-opt) optimizes the binary
    Then the zeroization writes are NOT removed by dead code elimination
    And the `zeroize` crate's `volatile_set` ensures the writes persist
    And a unit test verifies the memory region is zero post-zeroization

  Scenario: Multiple derivations reuse the same memory region
    Given Alice failed authentication and must re-enter her passphrase
    When the SDK performs a second Argon2id derivation
    Then the WASM module reuses the same linear memory region
    And the previous secret's memory was already zeroized
    And no ghost of the first secret remains

  # --- Error Cases ---

  Scenario: WASM instance terminated before zeroization
    Given the browser kills the WASM instance (tab crash, OOM kill)
    When the instance is terminated without calling zeroize
    Then the browser releases the WASM memory pages to the OS
    And the OS may or may not zero the pages (OS-dependent)
    And the SDK cannot prevent this — it is documented as an accepted risk
    And the exposure window was limited to the derivation+proof duration

  Scenario: Zeroization does not affect the proof bytes in JavaScript
    Given the proof was returned to JavaScript as a Uint8Array
    When WASM memory is zeroized
    Then the JavaScript Uint8Array containing the proof is unaffected
    And the proof can still be sent to the server
    And only the proof (public data) exists in JS memory

  Scenario: Garbage collector does not resurrect zeroized bytes
    Given the WASM memory was zeroized
    When the JavaScript garbage collector runs
    Then no finalizer or WeakRef resurrects the original secret bytes
    And the freed memory pages contain zeros, not the original secret

  Scenario: Console.log never contains secret bytes
    Given the SDK is in debug mode
    When a developer enables verbose logging
    Then no log statement outputs the derived secret, blinding factor, or pepper
    And logs contain only: timing, module status, proof length, error codes
    And a CI test scans the codebase for console.log of Uint8Array variables

---

## Adversarial Browser

### Feature: Resisting attacks from a compromised browser environment

  As the 2FApi security model
  I want to minimize what a compromised browser can learn about the user's secret
  So that even browser extensions, Spectre, or instrumented JS cannot trivially extract secrets

  # --- Happy Path ---

  Scenario: Secret never exists in JavaScript heap
    Given Alice types her passphrase
    When the SDK sends the passphrase string to WASM for derivation
    Then the derived secret (s, r) is computed entirely in WASM
    And the secret bytes are NEVER copied to a JavaScript ArrayBuffer
    And the only data returned to JS is the proof (96 bytes, public)
    And a compromised extension monitoring JS memory sees no secret material

  # --- Edge Cases ---

  Scenario: Passphrase string exists briefly in JS before WASM call
    Given Alice types "blue tiger fast moon" in the input field
    When the SDK reads the input value and passes it to WASM
    Then the passphrase string exists in the JS heap for the duration of the call
    And after the WASM function returns, the SDK overwrites the JS string reference
    And the input field value is cleared programmatically
    And the exposure window for the passphrase is < 100ms

  Scenario: Malicious extension hooks WASM imports
    Given a malicious extension monkey-patches WebAssembly.instantiate
    When the extension wraps WASM function calls to intercept arguments
    Then the extension sees the passphrase string (input to Argon2id)
    But the extension does NOT see the derived secret (stays inside WASM)
    And the extension would need to also extract the OPRF key + hardware key to be useful
    And this is documented: "passphrase exposure to JS is an accepted trade-off; the secret is protected by WASM isolation + OPRF + hardware binding"

  Scenario: Spectre-class side-channel attack on WASM memory
    Given an attacker exploits Spectre to read WASM linear memory from JS
    When the attacker reads memory during derivation
    Then the attacker may observe intermediate Argon2id state
    But the derivation time is limited (< 3 seconds)
    And the secret is zeroized immediately after proof generation
    And the attacker's window is the derivation + proof time only
    And even with the secret, the attacker still needs the OPRF key + hardware key
    And this is documented: "Spectre exposure window minimized to derivation duration"

  Scenario: SharedArrayBuffer is NOT used for secrets
    Given multiple tabs may be open on the same origin
    When the SDK allocates WASM memory
    Then the WASM Memory is backed by a standard ArrayBuffer (not SharedArrayBuffer)
    And other tabs cannot observe the WASM linear memory
    And no postMessage transfers secret-containing buffers

  # --- Error Cases ---

  Scenario: Extension steals proof — replay attack
    Given a malicious extension intercepts the proof sent to the server
    When the extension replays the proof in a separate request
    Then the server rejects the replay (nonce already consumed)
    And the proof is bound to a specific challenge nonce with TTL
    And the extension gains nothing from the intercepted proof

  Scenario: Extension modifies the challenge nonce
    Given a malicious extension intercepts the server's challenge response
    When the extension changes the nonce before the SDK receives it
    Then the SDK computes a proof with the modified nonce
    And the server rejects the proof (nonce does not match any issued challenge)
    And the attacker cannot forge a valid proof without the secret

  Scenario: Extension reads localStorage vault blob
    Given a malicious extension reads localStorage
    When the extension extracts the encrypted vault (Tier 1)
    Then the vault blob is encrypted with AES-256-GCM
    And the encryption key requires both the password AND the server pepper
    And the extension cannot decrypt the vault (missing server pepper)
    And offline brute-force is impossible (256-bit pepper entropy)

  Scenario: Compromised JS runtime instruments WASM memory reads
    Given the JS runtime is compromised and can read arbitrary WASM memory addresses
    When the attacker reads the memory region containing the derived secret
    Then the attacker observes the secret during the derivation+proof window
    And after zeroization, the memory region contains only zeros
    And the secret exposure is bounded by the zeroization timing
    And mitigation: the attacker still needs to correlate with the server pepper for vault unsealing
    And this is documented as "defense in depth — zeroization limits exposure, server pepper limits utility"

  Scenario: Attacker replaces the WASM binary with a backdoored version (CDN)
    Given the attacker serves a modified WASM binary from a compromised CDN
    When the SDK loads the binary
    Then the Subresource Integrity (SRI) hash check fails
    And the SDK refuses to use the modified binary
    And Alice sees "Security verification failed. Please reload."
    And no derivation or proof is attempted with the compromised binary

  Scenario: Supply chain attack on npm package @2fapi/crypto-wasm
    Given an attacker publishes a compromised version of @2fapi/crypto-wasm on npm
    When a developer installs the package
    Then the package's WASM binary hash does not match the pinned hash in lockfile
    And npm audit flags the discrepancy (if signatures are enabled)
    And the SDK's runtime SRI check catches the mismatch at load time
    And no compromised WASM is executed in production

  Scenario: Extension DOM-scrapes passphrase input fields
    Given a malicious extension uses MutationObserver to watch input fields
    When Alice types her passphrase "blue tiger fast moon"
    Then the extension can read the input values from the DOM (accepted risk)
    And MITIGATION: the passphrase alone cannot derive the vault key
    And the vault key requires: OPRF(server) + hardware_key(TPM) + passphrase
    And the extension would need to compromise all 3 factors simultaneously

---

## Expert Amendments — Randomness, Properties, Performance

### Feature: Cryptographic quality assurance (expert review amendments)

  # --- Amendment #1 (Cryptographer): WASM randomness source ---

  Scenario: WASM proof randomness sourced from crypto.getRandomValues
    Given the WASM module needs random nonces (k_s, k_r) for proof generation
    When the WASM binary is compiled
    Then the Rust code imports randomness via wasm-bindgen: js_sys::crypto().get_random_values()
    And the randomness is NOT sourced from OsRng (which may not compile to WASM)
    And the browser's crypto.getRandomValues() provides CSPRNG quality
    And a compile-time feature flag selects the randomness source per platform

  # --- Amendment #2 (Cryptographer): PIN vs passphrase derivation ---

  Scenario: PIN and passphrase use the same Argon2id algorithm with different inputs
    Given Bob enters PIN "847291" and Alice enters passphrase "blue tiger fast moon"
    When the SDK calls derive_credential for each
    Then both use identical Argon2id parameters (64MB, 3 iterations, parallelism 1)
    And the only difference is the input string
    And the derived secrets are different (different inputs produce different outputs)
    And the Argon2id algorithm does NOT vary based on credential type

  # --- Amendment #12 (QA): Property-based testing ---

  Scenario: Property-based test — derive → commit → prove → verify cycle
    Given any valid 4-word BIP-39 passphrase P
    And any valid salt (email, tenant_id)
    When the SDK derives (s, r) = Argon2id(P, salt)
    And computes C = s·G + r·H
    And generates a Sigma proof π for (s, r, C, nonce)
    Then verify(π, C, nonce) always succeeds
    And this property holds for all valid inputs (tested with fast-check, 10000 iterations)
    And no edge case produces a false negative

  # --- Amendment #13 (QA): End-to-end enrollment performance ---

  Scenario: End-to-end enrollment completes in under 30 seconds on mobile
    Given Bob uses a mid-range Android phone (Snapdragon 778)
    When Bob completes the full enrollment flow (Steps 1–5)
    Then the total time from Step 1 to completion is under 30 seconds
    And the Argon2id derivation accounts for the majority of the wait
    And no step takes more than 5 seconds individually
    And a CI benchmark test runs this scenario on a simulated mobile environment
