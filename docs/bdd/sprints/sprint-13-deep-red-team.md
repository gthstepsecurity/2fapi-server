# Sprint 13 — Deep Red Team Findings (3rd Pass)

## Context

After 12 sprints, 2 prior red team audits, and 940 tests, a 3rd deep adversarial
analysis uncovered 8 new vulnerabilities. This sprint addresses all of them.

---

## FIX 1 (CRITICAL): Zero Challenge on NAPI Failure

### Scenario: Transcript hasher failure throws instead of returning zeros

```gherkin
Given a NapiTranscriptHasher with a failing native module
When the hasher is called with any transcript bytes
Then it throws a TranscriptHashError
And does NOT silently return a zeroed 32-byte array
```

### Scenario: Zero challenge scalar causes proof rejection

```gherkin
Given a valid proof request with all preconditions passing
When the transcript hasher produces an all-zero challenge scalar
Then the proof is rejected with "verification_refused"
And the zero challenge is never passed to the equation verifier
```

### Scenario: Non-zero challenge proceeds with normal verification

```gherkin
Given a valid proof request with all preconditions passing
When the transcript hasher produces a non-zero challenge scalar
Then the proof equation verifier is called with that scalar
And the result depends on the equation verification outcome
```

---

## FIX 2 (HIGH): Verification Receipt Binding

### Scenario: Token issuance without receiptId is refused

```gherkin
Given a verification receipt store is wired into IssueTokenUseCase
When a token issuance is requested without a verificationReceiptId
Then the response is { success: false, error: "issuance_refused" }
And the audit log records "missing_verification_receipt"
```

### Scenario: Token issuance with valid receiptId succeeds

```gherkin
Given a receipt "receipt-123" exists in the receipt store for client "alice"
When a token issuance is requested with verificationReceiptId "receipt-123"
Then the token is issued successfully
And the receipt is consumed (cannot be reused)
```

### Scenario: Token issuance with already-consumed receiptId is refused

```gherkin
Given a receipt "receipt-123" was already consumed
When a token issuance is requested with verificationReceiptId "receipt-123"
Then the response is { success: false, error: "issuance_refused" }
And the audit log records "invalid_verification_receipt"
```

### Scenario: Token issuance with receiptId for different client is refused

```gherkin
Given a receipt "receipt-123" exists for client "alice"
When client "bob" requests token issuance with verificationReceiptId "receipt-123"
Then the response is { success: false, error: "issuance_refused" }
And the audit log records "receipt_client_mismatch"
```

### Scenario: VerifyProofUseCase generates a receiptId on success

```gherkin
Given a valid proof verification request
When the proof is verified successfully
Then the response includes a non-empty receiptId
```

### Scenario: Verification route passes receiptId to token issuance

```gherkin
Given the verification route receives a valid proof
When the proof is verified successfully
Then the resulting receiptId is passed to the token issuance request
```

---

## FIX 3 (MEDIUM): Dummy Domain Separation Tag Wrong Size

### Scenario: Dummy and real transcript paths produce same byte length

```gherkin
Given a proof request with an empty domain separation tag (precondition failure path)
When the dummy transcript is built
Then its byte length matches a transcript built with the real "2FApi-v1.0-Sigma" tag
And no timing side-channel reveals the precondition result
```

---

## FIX 4 (MEDIUM): IP Rate Limiter Map Unbounded

### Scenario: Map at maxEntries rejects new IP

```gherkin
Given an IP rate limiter configured with maxEntries = 3
And 3 distinct IPs have already been tracked
When a 4th new IP attempts to acquire
Then it is rejected (allowed = false)
And the response includes retryAfterSeconds
```

### Scenario: Existing IP at maxEntries still tracked

```gherkin
Given an IP rate limiter configured with maxEntries = 3
And 3 distinct IPs have already been tracked
When one of the 3 tracked IPs makes another request
Then it is allowed (if under per-IP rate limit)
```

---

## FIX 5 (MEDIUM): commitmentVersion Not Persisted

### Scenario: Save and restore client preserves commitmentVersion

```gherkin
Given a client with commitmentVersion = 3
When the client is saved to PostgreSQL and then retrieved
Then the retrieved client has commitmentVersion = 3
```

---

## FIX 6 (MEDIUM): Transcript Format Documentation

### Scenario: Canonical transcript format is documented

```gherkin
Given the 2FApi protocol documentation
When a developer reads docs/PROTOCOL.md
Then they find the canonical Fiat-Shamir transcript format specification
And a warning that Rust compute_challenge is not production-authoritative
```

---

## FIX 7 (LOW): Constant-Time requireNative

### Scenario: requireNative throws when native module not loaded

```gherkin
Given the native constant-time module has NOT been set
When requireNative() is called
Then it throws an error indicating the native module is required
```

### Scenario: requireNative succeeds when native module loaded

```gherkin
Given the native constant-time module HAS been set
When requireNative() is called
Then it does not throw
```

---

## FIX 8 (LOW): Remove serde feature from curve25519-dalek

### Scenario: Unnecessary serde feature removed

```gherkin
Given the crypto-core Cargo.toml
When the serde feature is removed from curve25519-dalek
Then the crate still compiles successfully
And the attack surface is reduced
```
