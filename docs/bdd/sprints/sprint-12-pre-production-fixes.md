# Sprint 12 — Pre-Production Critical Fixes

> Red Team audit findings: 10 priority fixes before production deployment.

## Priority Items

### FIX 1 (CRITICAL): StubAdminAuthenticator — Fail-Fast Guard
- **File**: `src/create-lifecycle-service.ts`
- **Risk**: Factory can be deployed with no real AdminAuthenticator, silently using a stub
- **Fix**: Require AdminAuthenticator explicitly; throw at startup if missing
- **Test**: Factory without authenticator throws; factory with authenticator works

### FIX 2 (HIGH): Challenge Request Timing Oracle
- **File**: `src/authentication-challenge/application/usecase/request-challenge.usecase.ts`
- **Risk**: Failure path executes fewer async operations than success path, leaking timing info
- **Fix**: Add dummy async operations on failure path to match success path timing
- **Test**: Verify capacityPercentage and findPending are called on failure path

### FIX 3 (HIGH): Commitment.equals Non-Constant-Time in Enrollment
- **File**: `src/client-registration/application/usecase/enroll-client.usecase.ts`
- **Risk**: Commitment comparison in enrollment uses early-return equals(), leaking byte position info
- **Fix**: Use constantTimeEqual from shared module for commitment comparison
- **Test**: Same commitment returns success; different commitment returns failure

### FIX 4 (HIGH): Channel Binding Empty in Resource/Rotation Routes
- **Files**: `src/api-gateway/routes/resource.routes.ts`, `src/api-gateway/routes/rotation.routes.ts`
- **Risk**: Routes pass empty string for channelBindingHash, bypassing channel binding protection
- **Fix**: Extract channel binding from X-Channel-Binding header; support strict/permissive modes
- **Test**: Strict mode without header returns 401; with header passes to validateToken; permissive mode skips

### FIX 5 (HIGH): IssueToken Without Proof Verification Binding
- **File**: `src/api-access-control/application/usecase/issue-token.usecase.ts`
- **Risk**: Token can be issued without proof of successful verification (no cryptographic binding)
- **Fix**: Require verificationReceiptId; add VerificationReceiptStore port; verify-then-issue binding
- **Test**: Valid receipt succeeds; missing receipt refused; reused receipt refused

### FIX 6 (HIGH): Challenge Consumption Atomicity
- **File**: `src/zk-verification/infrastructure/adapter/outgoing/atomic-challenge-consumer.ts`
- **Risk**: AtomicChallengeStore interface returns sync instead of async; missing atomicity contract
- **Fix**: Make atomicConsumeIfValid return Promise; add JSDoc contract; startup warning for in-memory
- **Test**: 10 parallel consumeIfValid calls — exactly 1 succeeds

### FIX 7 (HIGH): Enrollment TOCTOU Race Condition
- **File**: `src/client-registration/application/usecase/enroll-client.usecase.ts`
- **Risk**: Gap between findByIdentifier and save allows duplicate enrollment under concurrency
- **Fix**: Retry-on-conflict pattern: if save throws, re-check for idempotent case
- **Test**: Concurrent enrollment with same identifier — one succeeds, other gets idempotent or conflict-retry

### FIX 8 (HIGH): Rotation Rollback Inconsistency
- **File**: `src/client-registration/application/usecase/rotate-commitment.usecase.ts`
- **Risk**: Current ordering invalidates tokens before publishing event; rollback cannot undo invalidation
- **Fix**: Reorder: save -> publish event -> invalidate tokens/challenges; partial failure is safe
- **Test**: Event publish failure rolls back commitment without token invalidation; token invalidation failure is logged as warning

### FIX 9 (HIGH): Rate Limiting Disabled by Default
- **File**: `src/api-gateway/server.ts`
- **Risk**: Server can run without any rate limiting if option not provided
- **Fix**: Make rateLimiting config REQUIRED; provide createDevelopmentServer helper with permissive defaults
- **Test**: createServer without rateLimiting throws; createDevelopmentServer works with defaults

### FIX 10 (HIGH): Docker Default Credentials
- **File**: `docker-compose.yml`
- **Risk**: Hardcoded dev-password and ports exposed on 0.0.0.0
- **Fix**: Use env variable references with no defaults; bind to 127.0.0.1; add .env.example
- **Test**: N/A (infrastructure file)

## Acceptance Criteria
- All 905+ existing tests pass
- New tests written for each fix (TDD)
- TypeScript compiles without errors
- Each fix committed separately
