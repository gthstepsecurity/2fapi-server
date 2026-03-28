# Iteration 03 — Three Failures → OPRF Key Destroyed

> Generated on 2026-03-26
> Source: docs/bdd/prioritized-oprf-vault-scenarios.md, Scenario #33
> Bounded Context: Combined 3-Factor Vault
> Feature: Permanent vault wipe after threshold
> Priority: P2
> Est. TDD cycles: 3

## Scenario

```gherkin
Feature: Permanent vault wipe after threshold

  Scenario: Three failed unseal attempts destroy the OPRF key permanently
    Given the failure counter reached 3
    When the server triggers a wipe
    Then the OPRF key k is permanently deleted
    And even with the correct password + hardware, the vault is undecryptable
    And Alice must re-enroll via passphrase and re-seal the vault
```

## Domain Concepts

| Concept | Type | New/Existing | File |
|---------|------|-------------|------|
| HandleOprfEvaluateUseCase | Use case (server) | Existing | `application/usecase/handle-oprf-evaluate.ts` |
| UnsealVaultOprfUseCase | Use case (client) | Existing | `application/usecase/unseal-vault-oprf.ts` |
| VaultAttemptCounter | Value Object | Existing | `domain/model/vault-attempt-counter.ts` |
| OprfKey | Value Object | Existing | `domain/model/oprf-key.ts` |
| OprfKeyStore | Port (outgoing) | Existing | `domain/port/outgoing/oprf-key-store.ts` |

## TPP Analysis Summary

| # | Transformation | Contradiction | Est. Lines |
|---|---------------|---------------|------------|
| 1 | (2) nil → constant | — (first test, server wipe flow end-to-end) | ~0 |
| 2 | (3) constant → variable | Server-only test doesn't verify client vault deletion | ~0 |
| 3 | (4) unconditional → conditional | Wipe shown but irreversibility not proven | ~0 |
| **Total** | | | **~0** |

---

## Test Sequence

### Test 1 — nil → constant

**Intent**: Three consecutive failures on the server make OPRF evaluation impossible and destroy the key
**Transformation**: (2) nil → constant
**Contradiction**: — (first test, establishes the server-side wipe flow end-to-end)
**Why this order**: Server wipe is the prerequisite for all downstream behaviors

- [x] RED: `three_failures_destroy_oprf_key_and_refuse_evaluation`
- [x] GREEN: Validates existing server code — passed immediately
- [x] REFACTOR: N/A

---

### Test 2 — constant → variable

- [x] RED: `client_deletes_local_vault_after_server_wipe_on_third_failure`
- [x] GREEN: Validates existing client code — passed immediately
- [x] REFACTOR: N/A

---

### Test 3 — unconditional → conditional

- [x] RED: `correct_password_after_wipe_still_cannot_unseal`
- [x] GREEN: Validates existing code — permanence proven
- [x] REFACTOR: N/A

---

## Completion Criteria

- [x] All 3 tests pass (14/14 in file)
- [x] Full BDD scenario #33 is satisfied
- [x] Mutation testing: deferred
- [x] Code reviewed for SOLID compliance
- [x] Domain purity verified
- [ ] Committed with conventional message
