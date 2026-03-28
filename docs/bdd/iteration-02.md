# Iteration 02 — Wrong Password Detection via OPRF

> Generated on 2026-03-26
> Source: docs/bdd/prioritized-oprf-vault-scenarios.md, Scenario #32
> Bounded Context: Combined 3-Factor Vault
> Feature: Wrong password detection via OPRF
> Priority: P2
> Est. TDD cycles: 4

## Scenario

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

## Domain Concepts

| Concept | Type | New/Existing | File |
|---------|------|-------------|------|
| UnsealVaultOprfUseCase | Use case | Existing | `application/usecase/unseal-vault-oprf.ts` |
| UnsealVaultError | DTO | Existing (to enrich) | `domain/port/incoming/unseal-vault.ts` |
| OprfGateway | Port (outgoing) | Existing | `domain/port/outgoing/oprf-gateway.ts` |
| CryptoEngine | Port (outgoing) | Existing | `domain/port/outgoing/crypto-engine.ts` |

## TPP Analysis Summary

| # | Transformation | Contradiction | Est. Lines |
|---|---------------|---------------|------------|
| 1 | (3) constant → variable | Happy-path-only tests don't exercise GCM failure path | ~0 |
| 2 | (4) unconditional → conditional | Test 1 checks return but not reportFailure side effect | ~0 |
| 3 | (6) value → mutated value | err("WRONG_PASSWORD") string has no attemptsRemaining | ~5 |
| 4 | (10) expression → function | Zeroization on error path not verified | ~0 |
| **Total** | | | **~5** |

---

## Test Sequence

### Test 1 — constant → variable

**Intent**: A wrong password causes AES-GCM decryption to fail and the use case reports WRONG_PASSWORD
**Transformation**: (3) constant → variable
**Contradiction**: — (first test for error path; existing tests only cover happy path)
**Why this order**: Establish the basic error path before verifying side effects

- [x] RED: `wrong_password_produces_wrong_password_error_on_gcm_failure`
- [x] GREEN: Already implemented (L78-80) — test validates existing code (passed immediately)
- [x] REFACTOR: N/A

---

### Test 2 — unconditional → conditional

**Intent**: When decryption fails, the server is notified to increment the failure counter
**Transformation**: (4) unconditional → conditional
**Contradiction**: Test 1 verified the return value but not the reportFailure side effect — the call at L79 is untested
**Why this order**: Side effects must be verified after the basic error path is confirmed

- [x] RED: `wrong_password_reports_failure_to_server`
- [x] GREEN: Already implemented (L79) — test validates existing code (passed immediately)
- [x] REFACTOR: N/A

---

### Test 3 — value → mutated value

**Intent**: The error response includes attempts remaining so the user knows how many tries are left
**Transformation**: (6) value → mutated value
**Contradiction**: The current err("WRONG_PASSWORD") is a plain string with no attemptsRemaining — must enrich the error type
**Why this order**: After confirming the error path works, enrich it with useful data

- [x] RED: `wrong_password_error_includes_attempts_remaining`
- [x] GREEN: Added lastErrorDetail property with attemptsRemaining from OPRF response
- [x] REFACTOR: N/A (clean minimal addition)

---

### Test 4 — expression → function

**Intent**: Sensitive buffers (vault key, OPRF output) are zeroized even when decryption fails
**Transformation**: (10) expression → function
**Contradiction**: Iteration 01 Test 7 verified zeroization on happy path only — the GCM error path must also zeroize
**Why this order**: Security hardening after functional correctness of the error path

- [x] RED: `wrong_password_still_zeroizes_vault_key_and_oprf_output`
- [x] GREEN: Already implemented (finally block + L59) — test validates (passed immediately)
- [x] REFACTOR: N/A

---

## Completion Criteria

- [x] All 4 tests pass (11/11 in file + 1652 total suite)
- [x] Full BDD scenario #32 is satisfied (GCM fail → WRONG_PASSWORD + reportFailure + attemptsRemaining + zeroize)
- [x] Mutation testing: deferred (Stryker TS checker incompatible with packages/ layout)
- [x] Code reviewed for SOLID compliance (SRP: use case enriched minimally, DIP: ports only)
- [x] Domain purity verified (no infrastructure imports)
- [ ] Committed with conventional message
