# Sprint 23 — OPRF P1 Foundation

> Started: 2026-03-26
> Source: docs/bdd/prioritized-oprf-vault-scenarios.md (P1 scenarios)

## Layer 1 — Rust crypto-core OPRF primitives

- [x] RED: OPRF_DST constant exists and differs from Sigma DST
- [x] GREEN: Define OPRF_DST
- [x] RED: hash_to_group produces non-identity point
- [x] GREEN: Implement hash_to_group
- [x] RED: hash_to_group is deterministic
- [x] GREEN: Already passes (pure function)
- [x] RED: blind returns valid point + non-zero scalar
- [x] GREEN: Implement blind
- [x] RED: Two blindings of same input produce different B
- [x] GREEN: Already passes (random r)
- [x] RED: generate_oprf_key returns non-zero scalar
- [x] GREEN: Implement generate_oprf_key
- [x] RED: evaluate returns valid non-identity point
- [x] GREEN: Implement evaluate
- [x] RED: unblind(evaluate(blind(P,r),k),r) = k·P (correctness)
- [x] GREEN: Implement unblind
- [x] RED: Same password → same U; diff password → diff U
- [x] GREEN: Already passes (deterministic math)
- [x] RED: Replayed E unblinds to wrong value
- [x] GREEN: Already passes (different r)
- [x] RED: Identity and non-canonical points rejected
- [x] GREEN: Add validation functions
- [x] RUN: cargo test — 112 passed (18 new OPRF tests)

## Layer 2 — TypeScript domain + use cases

- [x] RED: OprfKey model — generate, restore, destroy
- [x] GREEN: Implement OprfKey
- [x] RED: HandleOprfEvaluate — rejects invalid blinded point
- [x] GREEN: Add validation (length check)
- [x] RED: HandleOprfEvaluate — returns error for missing OPRF key
- [x] GREEN: Add null check
- [x] RED: HandleOprfEvaluate — refuses eval after wipe
- [x] GREEN: Check isWiped flag + delete key
- [x] RED: HandleOprfEvaluate — checks counter before eval
- [x] GREEN: Gate evaluation on counter
- [x] RED: HandleOprfEvaluate — generates + stores OPRF key on seal
- [x] GREEN: Implement seal flow
- [x] RED: HandleOprfEvaluate — evaluates and returns E
- [x] GREEN: Implement evaluation (simulated scalar mult)
- [x] RED: Client — server unreachable → fallback error
- [x] GREEN: Error handling test
- [x] RED: Attack test — offline vault indecryptable (2^256 brute-force)
- [x] GREEN: Mathematical proof test
- [x] RED: Proof of possession verified in enrollment
- [x] GREEN: Verify existing requirement
- [x] RUN: npx vitest run tests/client-sdk/ — 160 passed, 0 failed

## Consolidation

- [x] RUN: npx vitest run — 1613 passed, 0 failed
- [x] RUN: cargo test — 112 passed (18 new OPRF + 94 existing)
- [x] UPDATE: sprint file complete
