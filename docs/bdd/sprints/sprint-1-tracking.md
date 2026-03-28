# Sprint 1 Tracking — Client Enrollment

> Branch: `feature/sprint-1-client-enrollment`
> Lead: Software Architect + Backend Engineer
> Started: 2026-03-18

## Module Structure

```
src/
├── client-registration/
│   ├── domain/
│   │   ├── model/
│   │   │   ├── client.ts                    # Aggregate root
│   │   │   ├── client-id.ts                 # Value Object (opaque, CSPRNG 128-bit)
│   │   │   ├── commitment.ts                # Value Object (32-byte Ristretto255)
│   │   │   ├── client-status.ts             # Value Object (active | revoked)
│   │   │   └── enrollment-receipt.ts        # Value Object (returned to caller)
│   │   ├── event/
│   │   │   └── client-enrolled.ts           # Domain Event
│   │   ├── port/
│   │   │   ├── incoming/
│   │   │   │   └── enroll-client.ts         # Driving port (use case interface)
│   │   │   └── outgoing/
│   │   │       ├── client-repository.ts     # Driven port
│   │   │       ├── commitment-verifier.ts   # Driven port (validates commitment bytes)
│   │   │       ├── proof-of-possession-verifier.ts  # Driven port (Sigma protocol)
│   │   │       ├── id-generator.ts          # Driven port (CSPRNG)
│   │   │       ├── audit-logger.ts          # Driven port
│   │   │       └── event-publisher.ts       # Driven port
│   │   └── service/
│   │       └── enrollment-policy.ts         # Domain service (validation pipeline)
│   ├── application/
│   │   ├── usecase/
│   │   │   └── enroll-client.usecase.ts     # Use case implementation
│   │   └── dto/
│   │       ├── enroll-client.request.ts     # Input DTO
│   │       └── enroll-client.response.ts    # Output DTO
│   └── infrastructure/
│       └── adapter/
│           └── outgoing/
│               ├── in-memory-client-repository.ts
│               ├── stub-commitment-verifier.ts
│               ├── stub-proof-of-possession-verifier.ts
│               ├── crypto-random-id-generator.ts
│               ├── console-audit-logger.ts
│               └── noop-event-publisher.ts
├── shared/
│   ├── public-parameters.ts                 # Utility: generator derivation & verification
│   └── errors.ts                            # Enrollment error types
├── index.ts                                 # Library entry point, exports & factory
└── create-enrollment-service.ts             # Factory function
```

```
tests/
├── client-registration/
│   ├── domain/
│   │   ├── model/
│   │   │   ├── client.test.ts
│   │   │   ├── client-id.test.ts
│   │   │   ├── commitment.test.ts
│   │   │   └── enrollment-receipt.test.ts
│   │   └── service/
│   │       └── enrollment-policy.test.ts
│   ├── application/
│   │   └── usecase/
│   │       └── enroll-client.usecase.test.ts
│   └── infrastructure/
│       └── adapter/
│           └── outgoing/
│               └── in-memory-client-repository.test.ts
├── shared/
│   └── public-parameters.test.ts
└── acceptance/
    └── client-enrollment.acceptance.test.ts
```

## Developer Assignment

| Phase | Developer | Scope |
|-------|-----------|-------|
| 0 | Backend Engineer | Project setup (npm, tsconfig, vitest, structure) |
| 1 | Software Architect + Backend Engineer | Value Objects (domain/model) |
| 2 | Software Architect | Ports (domain/port) — interfaces only |
| 3 | Backend Engineer | Domain Service (enrollment-policy) |
| 4 | Backend Engineer | Use Case (enroll-client.usecase) |
| 5 | Backend Engineer | Reference Adapters (infrastructure) |
| 6 | Backend Engineer | Factory + Library Exports |
| 7 | QA/Test Architect + Backend Engineer | Acceptance tests + property-based tests |

## TDD Phases

### Phase 0 — Project Setup
- [ ] Initialize npm project with TypeScript strict
- [ ] Configure Vitest
- [ ] Configure fast-check
- [ ] Create directory structure
- [ ] Verify empty test suite passes

### Phase 1 — Value Objects (domain/model) [SRP, OCP]
- [ ] RED: Commitment rejects non-32-byte input
- [ ] GREEN: Commitment value object with byte length validation
- [ ] REFACTOR: Extract validation

- [ ] RED: Commitment rejects all-zero bytes (identity element)
- [ ] GREEN: Add identity element check
- [ ] REFACTOR

- [ ] RED: Commitment accepts valid 32-byte input
- [ ] GREEN: Commitment stores bytes
- [ ] REFACTOR

- [ ] RED: Commitment equality is byte-exact comparison
- [ ] GREEN: Implement equals()
- [ ] REFACTOR

- [ ] RED: ClientId is opaque 128-bit minimum
- [ ] GREEN: ClientId value object
- [ ] REFACTOR

- [ ] RED: ClientId equality
- [ ] GREEN: Implement equals()
- [ ] REFACTOR

- [ ] RED: Client entity created with id, identifier, commitment, status=active
- [ ] GREEN: Client aggregate root
- [ ] REFACTOR

- [ ] RED: EnrollmentReceipt contains reference identifier
- [ ] GREEN: EnrollmentReceipt value object
- [ ] REFACTOR

- [ ] Mutation testing on Phase 1
- [ ] Commit: "feat(domain): add value objects for client registration"

### Phase 2 — Ports / Interfaces (domain/port) [DIP, ISP]
- [ ] Define ClientRepository port (findByIdentifier, save, existsByIdentifier)
- [ ] Define CommitmentVerifier port (isValidEncoding, isCanonical, isIdentityElement)
- [ ] Define ProofOfPossessionVerifier port (verify — constant-time contract documented)
- [ ] Define IdGenerator port (generate → ClientId)
- [ ] Define AuditLogger port (log event)
- [ ] Define EventPublisher port (publish domain event)
- [ ] Define EnrollClient driving port (execute → EnrollClientResponse)
- [ ] Define EnrollClientRequest DTO
- [ ] Define EnrollClientResponse DTO
- [ ] Define EnrollmentError types (exhaustive, indistinguishable externally)
- [ ] Commit: "feat(domain): define ports and DTOs for enrollment"

### Phase 3 — Domain Service: Enrollment Policy [SRP, OCP]
- [ ] RED: Policy rejects missing commitment
- [ ] GREEN: First validation step
- [ ] REFACTOR

- [ ] RED: Policy rejects non-canonical encoding (pipeline step 1)
- [ ] GREEN: Add canonical check via CommitmentVerifier
- [ ] REFACTOR

- [ ] RED: Policy rejects invalid group element (pipeline step 2)
- [ ] GREEN: Add valid element check via CommitmentVerifier
- [ ] REFACTOR

- [ ] RED: Policy rejects identity element (pipeline step 3)
- [ ] GREEN: Add identity check via CommitmentVerifier
- [ ] REFACTOR

- [ ] RED: Policy rejects missing proof of possession
- [ ] GREEN: Add proof presence check
- [ ] REFACTOR

- [ ] RED: Policy rejects invalid proof of possession (pipeline step 4)
- [ ] GREEN: Add proof verification via ProofOfPossessionVerifier
- [ ] REFACTOR

- [ ] RED: Policy accepts valid commitment + valid proof
- [ ] GREEN: Return success
- [ ] REFACTOR: Extract validation pipeline

- [ ] RED: Policy rejects all-zero proof of possession
- [ ] GREEN: Handle trivially invalid proof
- [ ] REFACTOR

- [ ] RED: Policy rejects degenerate scalar values in proof
- [ ] GREEN: Handle degenerate values
- [ ] REFACTOR

- [ ] Mutation testing on Phase 3
- [ ] Commit: "feat(domain): enrollment policy with validation pipeline"

### Phase 4 — Use Case (application/usecase) [SRP, DIP]
- [ ] RED: Enrollment succeeds with valid inputs → stored + receipt returned
- [ ] GREEN: Use case orchestrates policy + repository + receipt
- [ ] REFACTOR

- [ ] RED: Enrollment rejects duplicate identifier
- [ ] GREEN: Check existsByIdentifier before enrollment
- [ ] REFACTOR

- [ ] RED: Error responses are indistinguishable (no enumeration)
- [ ] GREEN: Map all errors to generic failure
- [ ] REFACTOR

- [ ] RED: Enrollment publishes ClientEnrolled event on success
- [ ] GREEN: Call EventPublisher
- [ ] REFACTOR

- [ ] RED: Enrollment logs success to audit logger
- [ ] GREEN: Call AuditLogger on success
- [ ] REFACTOR

- [ ] RED: Enrollment logs failure to audit logger (without revealing commitment owner)
- [ ] GREEN: Call AuditLogger on failure with sanitized data
- [ ] REFACTOR

- [ ] RED: Idempotent retry (same identifier + same commitment) → same receipt
- [ ] GREEN: Detect and return existing enrollment
- [ ] REFACTOR

- [ ] RED: Concurrent duplicate enrollment → exactly one succeeds
- [ ] GREEN: Repository.save with optimistic concurrency
- [ ] REFACTOR

- [ ] RED: Replay of complete enrollment request → idempotent
- [ ] GREEN: Handle gracefully
- [ ] REFACTOR

- [ ] RED: Request with unexpected fields → ignored (lenient parsing)
- [ ] GREEN: DTO ignores unknown fields
- [ ] REFACTOR

- [ ] RED: Rate limiting check (if rate limiter port provided)
- [ ] GREEN: Optional rate limiter port integration
- [ ] REFACTOR

- [ ] RED: Malleable commitment variant → rejected by policy
- [ ] GREEN: Already handled by proof of possession verification
- [ ] REFACTOR: Verify test actually tests malleability

- [ ] Mutation testing on Phase 4
- [ ] Commit: "feat(application): enrollment use case with full error handling"

### Phase 5 — Reference Adapters (infrastructure) [LSP, DIP]
- [ ] RED: InMemoryClientRepository saves and retrieves clients
- [ ] GREEN: Map-based implementation
- [ ] REFACTOR

- [ ] RED: InMemoryClientRepository.existsByIdentifier returns true for known
- [ ] GREEN: Implement lookup
- [ ] REFACTOR

- [ ] RED: InMemoryClientRepository handles concurrent save (optimistic locking)
- [ ] GREEN: Add version check
- [ ] REFACTOR

- [ ] RED: StubCommitmentVerifier returns configurable results
- [ ] GREEN: Stub with preset responses
- [ ] REFACTOR

- [ ] RED: StubProofOfPossessionVerifier returns configurable results
- [ ] GREEN: Stub with preset responses
- [ ] REFACTOR

- [ ] RED: CryptoRandomIdGenerator generates unique 128-bit IDs
- [ ] GREEN: Use crypto.randomBytes
- [ ] REFACTOR

- [ ] Mutation testing on Phase 5
- [ ] Commit: "feat(infrastructure): reference adapters for enrollment"

### Phase 6 — Factory + Library Exports [OCP, DIP]
- [ ] RED: createEnrollmentService assembles all dependencies
- [ ] GREEN: Factory function
- [ ] REFACTOR

- [ ] RED: Library index exports all public types
- [ ] GREEN: index.ts with re-exports
- [ ] REFACTOR

- [ ] Commit: "feat(lib): factory function and public API exports"

### Phase 7 — Acceptance Tests + Property-Based [Quality]
- [ ] Acceptance test: full enrollment happy path via factory
- [ ] Acceptance test: all error paths return indistinguishable errors
- [ ] Property-based: for any valid commitment + valid proof → enrollment succeeds
- [ ] Property-based: for any invalid proof → enrollment fails
- [ ] Property-based: enrollment receipt is deterministic for same inputs (idempotency)
- [ ] Final mutation testing (full scope)
- [ ] Commit: "test: acceptance and property-based tests for enrollment"

## Completion Criteria
- [ ] All 20 scenarios covered by tests
- [ ] Mutation kill rate ≥ 95% (100% target)
- [ ] Zero architecture violations (domain has no infra imports)
- [ ] All ports documented with contracts
- [ ] Factory function works end-to-end
- [ ] Library exports verified
