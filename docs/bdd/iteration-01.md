# Iteration 01 — Unseal Vault with Password + OPRF (Tier 1a)

> Generated on 2026-03-26
> Source: docs/bdd/prioritized-oprf-vault-scenarios.md, Scenario #25
> Bounded Context: Combined 3-Factor Vault
> Feature: Two-factor vault unseal (Tier 1a)
> Priority: P2
> Est. TDD cycles: 7

## Scenario

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

## Domain Concepts

| Concept | Type | New/Existing | File |
|---------|------|-------------|------|
| UnsealVaultRequest | DTO | Existing | `domain/port/incoming/unseal-vault.ts` |
| UnsealVaultResponse | DTO | Existing | `domain/port/incoming/unseal-vault.ts` |
| VaultEntry | Value Object | Existing | `domain/model/vault-entry.ts` |
| VaultLocalStore | Port (outgoing) | Existing | `domain/port/outgoing/vault-local-store.ts` |
| OprfGateway | Port (outgoing) | **New** | `domain/port/outgoing/oprf-gateway.ts` |
| CryptoEngine (extended) | Port (outgoing) | **Extended** | `domain/port/outgoing/crypto-engine.ts` |
| UnsealVaultOprfUseCase | Use case | **New** | `application/usecase/unseal-vault-oprf.ts` |

## TPP Analysis Summary

| # | Transformation | Contradiction | Est. Lines |
|---|---------------|---------------|------------|
| 1 | (2) nil → constant | — (first test) | ~5 |
| 2 | (3) constant → variable | NO_VAULT_FOUND constant doesn't handle expired vault | ~4 |
| 3 | (4) unconditional → conditional | Code doesn't contact OPRF server at all | ~8 |
| 4 | (4) conditional (new branch) | Code assumes server always returns "allowed" | ~3 |
| 5 | (6) value → mutated value | Code has no key derivation from OPRF output | ~6 |
| 6 | (8) selection → iteration | Code derives key but doesn't decrypt vault | ~8 |
| 7 | (10) expression → function | Sensitive buffers left in memory after use | ~5 |
| **Total** | | | **~39** |

---

## Test Sequence

### Test 1 — nil → constant

**Intent**: An OPRF unseal use case exists and rejects when no vault is found locally
**Transformation**: (2) nil → constant
**Contradiction**: — (first test, establishes the baseline)
**Why this order**: Simplest failure case — no vault in store

- [x] RED: `unseal_vault_oprf_returns_no_vault_found_when_store_is_empty`
- [x] GREEN: Create UnsealVaultOprfUseCase with constructor + load + return err("NO_VAULT_FOUND")
- [x] REFACTOR: N/A

---

### Test 2 — constant → variable

**Intent**: An expired vault is detected and deleted before any server communication
**Transformation**: (3) constant → variable
**Contradiction**: The constant "NO_VAULT_FOUND" return doesn't handle the case where a vault exists but is expired
**Why this order**: TTL check must happen before expensive OPRF server call

- [x] RED: `unseal_vault_oprf_returns_vault_expired_and_deletes_entry`
- [x] GREEN: Add entry.isExpired() check + localStore.delete() + return err("VAULT_EXPIRED")
- [x] REFACTOR: N/A

---

### Test 3 — unconditional → conditional (OPRF server interaction)

**Intent**: The use case sends a blinded password to the OPRF server and receives an evaluation
**Transformation**: (4) unconditional → conditional
**Contradiction**: The code doesn't contact the server at all — now it must branch on server response status
**Why this order**: Server OPRF interaction is the critical new behavior, must be tested before decryption

- [x] RED: `unseal_vault_oprf_calls_oprf_gateway_with_blinded_point`
- [x] GREEN: Add crypto.oprfBlind(password) → oprfGateway.requestEvaluation(blinded) → store response
- [x] REFACTOR: N/A

---

### Test 4 — conditional (wiped branch)

**Intent**: When the OPRF server reports the vault is wiped, the local vault is deleted and an error is returned
**Transformation**: (4) unconditional → conditional (new branch)
**Contradiction**: Code assumes server always returns "allowed" — must handle "wiped" status
**Why this order**: Error paths before happy path completion

- [x] RED: `unseal_vault_oprf_returns_vault_wiped_and_deletes_entry`
- [x] GREEN: Add if (response.status === "wiped") branch + SERVER_UNREACHABLE catch
- [x] REFACTOR: N/A

---

### Test 5 — value → mutated value (OPRF key derivation)

**Intent**: The vault key is derived from the OPRF output U via HKDF, not from a plaintext pepper
**Transformation**: (6) value → mutated value
**Contradiction**: Code receives the server evaluation but has no key derivation step — U must be transformed into vault_key
**Why this order**: Key derivation is the core OPRF innovation — must work before decrypt

- [x] RED: `unseal_vault_oprf_derives_vault_key_from_oprf_output`
- [x] GREEN: Add crypto.oprfUnblind(evaluated, r) → U, then crypto.deriveVaultKeyFromOprf(U, deviceId) → vault_key
- [x] REFACTOR: N/A

---

### Test 6 — selection → iteration (full decrypt + secret extraction)

**Intent**: The vault is decrypted with the OPRF-derived key and the secret (s, r) is returned
**Transformation**: (8) selection → iteration (extract 2 scalars from 64-byte plaintext)
**Contradiction**: Code derives the key but doesn't decrypt — must complete the full happy path
**Why this order**: Final functional step — the vault opens and Bob is authenticated

- [x] RED: `unseal_vault_oprf_decrypts_vault_and_returns_secret`
- [x] GREEN: Add crypto.decrypt(vaultKey, encrypted) → plaintext, extract secret + blinding, return ok
- [x] REFACTOR: skipped (pattern similar to UnsealVaultUseCase but OPRF-specific — no premature abstraction)

---

### Test 7 — expression → function (zeroization)

**Intent**: All sensitive intermediate values (OPRF output U, vault key, plaintext) are zeroized after use
**Transformation**: (10) expression → function
**Contradiction**: Code leaves sensitive buffers in memory after successful decryption — must add cleanup
**Why this order**: Security hardening after functional correctness is established

- [x] RED: `unseal_vault_oprf_zeroizes_all_sensitive_material`
- [x] GREEN: Add crypto.zeroize() calls for oprfOutput, vaultKey, plaintext in finally blocks
- [x] REFACTOR: try/finally verified — vaultKey in finally, oprfOutput before decrypt, plaintext after extract

---

## Completion Criteria

- [x] All 7 tests pass (7/7 + 1648 total suite)
- [x] Full BDD scenario #25 is satisfied
- [x] Mutation testing: deferred to /mutation-guard (Stryker TS checker incompatible with packages/)
- [x] Code reviewed for SOLID compliance (SRP: one use case, DIP: depends on ports only)
- [x] Domain purity verified (no infrastructure imports in use case)
- [ ] Committed with conventional message
