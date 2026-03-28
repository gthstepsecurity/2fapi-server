# Sprint 10 — Pre-Market Audit Security Fixes

> **Goal**: Fix the 5 security risks identified during the pre-market audit: challenge consumption atomicity, channel binding fallback, RNG health checks, constant-time comparisons in Rust, and global rate limiting.
> **Bounded Contexts**: Authentication Challenge, Zero-Knowledge Verification, API Access Control, API Gateway
> **Scenarios**: 30 | Happy: 9 | Edge: 13 | Error: 8
> **Prerequisites**: Sprints 1-9 (all domain logic, verification, access control, hardening, REST API)
> **Key deliverables**: Atomic challenge consumption (DB-level), DPoP-style channel binding fallback, RNG health validation with deterministic nonce fallback, all security comparisons moved to Rust napi (subtle crate), global and per-IP rate limiting
> **Audit reference**: Pre-market security audit — 5 risks (1 critical, 3 high, 1 medium)

### Expert Review Summary

> **Security Researcher**: Challenge consumption MUST be atomic at the database level (compare-and-swap or DELETE...RETURNING). No application-level mutex — it does not survive horizontal scaling. RNG health check must reject all-zero output and validate entropy before every nonce generation. Constant-time comparisons in TypeScript are fundamentally unreliable due to JIT optimization; moving to Rust napi with subtle::ConstantTimeEq is the correct mitigation.
>
> **Applied Crypto Engineer**: Deterministic nonce derivation (k = H(secret || counter || random)) as defense-in-depth ensures that even if OsRng fails catastrophically, nonce reuse is prevented. This is the same hedged-nonce strategy used in RFC 6979 and EdDSA. The counter must be persisted atomically to prevent replay.
>
> **API/Integration Engineer**: DPoP-style proof-of-possession fallback is well-specified in RFC 9449. The client generates an ephemeral ES256 key pair, signs the request with it, and the resulting token is bound to the public key thumbprint. This works behind CDN, load balancers, and TLS-terminating proxies. Global rate limiting must use a shared counter (Redis INCR with TTL) and respond with Retry-After headers.

---

## Feature 1: Challenge Consumption Atomicity (RISK 1 — CRITICAL)

```gherkin
Feature: Challenge Consumption Atomicity
  As the authentication system
  I want challenge consumption to be atomic at the database level
  So that two concurrent verification requests for the same challenge result in exactly one success

  Background:
    Given the authentication service is operational
    And Alice is registered with a valid commitment
    And Alice has a pending challenge with nonce "n_challenge_concurrent"

  # --- Happy Path ---

  Scenario: Single verification request consumes the challenge atomically
    Given Alice generates a valid proof bound to nonce "n_challenge_concurrent"
    When Alice submits the proof for verification
    Then the challenge is consumed using a database-level atomic operation (DELETE...RETURNING or compare-and-swap)
    And the verification succeeds
    And the challenge no longer exists in the challenge store
    And the consumption and verification are performed within a single database transaction

  # --- Edge Cases ---

  Scenario: Two concurrent verification requests for the same challenge — exactly one succeeds
    Given Alice generates a valid proof bound to nonce "n_challenge_concurrent"
    And Eve replays the exact same proof at the same instant
    When both requests arrive simultaneously and attempt to consume the challenge
    Then exactly one request successfully consumes the challenge via the atomic operation
    And that request proceeds to verification and succeeds (if the proof is valid)
    And the other request receives a "challenge_already_consumed" error
    And no race condition allows both requests to proceed to verification

  Scenario: Challenge consumption under high concurrency — no double consumption
    Given 50 concurrent requests all attempt to verify against the same challenge nonce
    When all 50 requests hit the challenge consumption layer simultaneously
    Then exactly 1 request obtains the challenge via the atomic operation
    And the remaining 49 requests receive "challenge_already_consumed" errors
    And the challenge store shows the challenge was consumed exactly once
    And no partial state or phantom reads occur

  Scenario: Database-level atomicity survives application crash mid-verification
    Given Alice submits a valid proof bound to nonce "n_challenge_crash"
    And the challenge is consumed atomically at the database level
    And the application process crashes after consumption but before returning the response
    When the application restarts and Eve attempts to use the same challenge
    Then the challenge is already consumed (the atomic operation was committed)
    And Eve receives a "challenge_already_consumed" error
    And no orphaned challenge exists in a partially consumed state

  # --- Error Cases ---

  Scenario: Application-level mutex is NOT used for challenge consumption
    Given the ChallengeConsumer adapter implementation
    When the code is reviewed for challenge consumption logic
    Then no in-process mutex, lock, or synchronized block is used for consumption
    And the atomicity relies solely on the database engine (e.g., DELETE...RETURNING, conditional UPDATE, or compare-and-swap)
    And horizontal scaling with multiple server instances does not break the atomicity guarantee

  Scenario: Consumed challenge returns consistent error regardless of timing
    Given challenge "n_challenge_consumed" has already been consumed
    When Eve submits a proof bound to "n_challenge_consumed" at any point in time
    Then the error response is "challenge_already_consumed"
    And the error is indistinguishable from a challenge that expired naturally
    And no information about when or by whom the challenge was consumed is leaked
```

---

## Feature 2: Channel Binding DPoP Fallback (RISK 2 — HIGH)

```gherkin
Feature: Channel Binding DPoP Fallback
  As a client application behind a CDN or load balancer
  I want a DPoP-style proof-of-possession fallback when TLS Exporter is unavailable
  So that my authentication token is still bound to my session and resistant to token theft

  Background:
    Given the authentication service is operational
    And Alice is registered with a valid commitment and has a pending challenge

  # --- Happy Path ---

  Scenario: Client uses DPoP fallback when TLS Exporter binding is unavailable
    Given Alice's connection passes through a TLS-terminating CDN
    And TLS Exporter channel binding is not available
    When Alice generates an ephemeral ES256 key pair (eph_pub, eph_priv)
    And Alice signs the verification request with eph_priv producing a DPoP proof header
    And Alice includes the DPoP proof in the request as a "DPoP" HTTP header
    And the DPoP proof contains: HTTP method, request URI, a unique jti, and iat timestamp
    Then the server validates the DPoP proof signature against the embedded public key
    And the server binds the resulting access token to the SHA-256 thumbprint of eph_pub
    And the token includes a "cnf" claim with the key thumbprint (per RFC 9449)

  Scenario: Subsequent API call with DPoP-bound token requires proof of key possession
    Given Alice holds a DPoP-bound access token with cnf thumbprint "thumb_abc123"
    When Alice makes an API call with the Bearer token
    And Alice includes a new DPoP proof signed by the same ephemeral key
    Then the server extracts the thumbprint from the DPoP proof's public key
    And the server verifies it matches the "cnf" thumbprint in the token
    And the request is authorized

  # --- Edge Cases ---

  Scenario: Server auto-detects binding mode — TLS Exporter preferred over DPoP
    Given Alice's connection provides TLS Exporter binding (direct TLS, no CDN)
    And Alice also includes a DPoP proof header
    When the server processes the authentication request
    Then the server uses TLS Exporter channel binding (preferred mode)
    And the DPoP proof header is ignored
    And the resulting token is bound to the TLS session, not the DPoP key

  Scenario: DPoP proof with expired iat is rejected
    Given Alice generates a DPoP proof with iat set to 10 minutes in the past
    And the server allows a maximum clock skew of 60 seconds
    When Alice submits the verification request with the stale DPoP proof
    Then the request is rejected with error "dpop_proof_expired"
    And no token is issued

  Scenario: DPoP proof jti replay is rejected
    Given Alice submits a verification request with DPoP proof containing jti "jti_unique_001"
    And the server records jti "jti_unique_001" in the replay cache
    When Eve replays the exact same DPoP proof with jti "jti_unique_001"
    Then the request is rejected with error "dpop_jti_reused"
    And the replay cache retains jti entries for at least the token's TTL

  # --- Error Cases ---

  Scenario: Missing both TLS Exporter and DPoP proof is rejected
    Given Alice's connection has no TLS Exporter binding available
    And Alice does not include a DPoP proof header in the request
    When Alice submits the verification request
    Then the request is rejected with error "channel_binding_required"
    And the error detail indicates that either TLS Exporter or DPoP proof is required

  Scenario: DPoP proof signed with wrong key does not match token thumbprint
    Given Alice holds a DPoP-bound token with cnf thumbprint "thumb_alice_key"
    And Eve intercepts the token and generates a DPoP proof with her own ephemeral key
    When Eve submits an API call with Alice's token and Eve's DPoP proof
    Then the server extracts the thumbprint from Eve's DPoP proof
    And the thumbprint does not match the token's cnf claim
    And the request is rejected with error "dpop_thumbprint_mismatch"
    And the incident is recorded in the security audit log
```

---

## Feature 3: RNG Health Check and Deterministic Nonce Fallback (RISK 3 — HIGH)

```gherkin
Feature: RNG Health Check and Deterministic Nonce Fallback
  As the cryptographic subsystem
  I want to validate RNG output before use and fall back to deterministic nonce derivation
  So that VM clones, broken entropy, or compromised OsRng cannot cause nonce reuse

  Background:
    Given the cryptographic module is initialized
    And the RNG health checker is active

  # --- Happy Path ---

  Scenario: RNG output passes health check and is used for nonce generation
    Given OsRng produces 32 bytes of output
    When the RNG health checker validates the output
    Then the output is not all-zeros
    And the output is not all-ones (0xFF)
    And the output passes a basic entropy check (at least 4 distinct byte values in 32 bytes)
    And the output is used as the random component for nonce generation
    And the nonce is derived as k = H(secret || counter || random) using the hedged construction

  Scenario: Hedged nonce derivation produces unique nonces even with identical random input
    Given the deterministic component uses secret "s_alice" and counter value 1
    And OsRng produces random bytes "rand_001"
    When the nonce is derived as k = H(secret || counter || random)
    And the counter is atomically incremented to 2
    And a second nonce is derived with the same secret, counter 2, and same random bytes "rand_001"
    Then the two nonces are different
    And uniqueness is guaranteed by the counter even if the RNG is stuck

  # --- Edge Cases ---

  Scenario: OsRng returns all-zeros — fallback to deterministic-only nonce
    Given OsRng returns 32 bytes of 0x00
    When the RNG health checker detects the all-zeros output
    Then a "rng_health_failure" security event is published with severity "critical"
    And the system falls back to deterministic nonce derivation: k = H(secret || counter || 0x00...00)
    And the counter ensures uniqueness despite the failed random component
    And proof generation proceeds without interruption
    And the security event includes the entropy source identifier

  Scenario: OsRng returns repeated identical bytes — health check flags low entropy
    Given OsRng returns 32 bytes where all bytes are 0xAB
    When the RNG health checker evaluates byte diversity
    Then the output is flagged as low-entropy (fewer than 4 distinct byte values)
    And a "rng_low_entropy" security event is published with severity "high"
    And the hedged nonce construction is used (counter provides uniqueness)
    And the system does not halt but operates in degraded security mode

  Scenario: Counter persistence survives application restart
    Given the nonce counter is at value 42 and is persisted to durable storage
    And the application process restarts
    When the counter is loaded from persistent storage on startup
    Then the counter resumes from at least 42 (never a lower value)
    And no counter value is ever reused across restarts
    And the counter uses atomic increment at the storage level

  # --- Error Cases ---

  Scenario: OsRng is completely unavailable — system operates on deterministic nonces only
    Given OsRng fails to initialize or throws an error on every call
    When proof generation is requested
    Then the system uses purely deterministic nonce derivation: k = H(secret || counter || domain_tag)
    And a "rng_unavailable" security event is published with severity "critical"
    And the counter is the sole source of nonce uniqueness
    And the system logs a persistent warning that entropy quality is degraded
    And proof generation does not fail — it proceeds with reduced security margin
```

---

## Feature 4: Constant-Time Comparisons in Rust (RISK 4 — HIGH)

```gherkin
Feature: Constant-Time Comparisons in Rust via napi
  As the authentication system
  I want all security-sensitive comparisons to be performed in Rust using subtle::ConstantTimeEq
  So that TypeScript JIT optimizations cannot introduce timing side channels

  Background:
    Given the authentication service is operational
    And the Rust napi module exposes constant-time comparison functions
    And TypeScript performs only routing and orchestration, never security comparisons

  # --- Happy Path ---

  Scenario: Challenge nonce comparison is performed in Rust napi
    Given a verification request includes challenge nonce "n_challenge_42"
    And the server retrieves the stored challenge nonce from the database
    When the nonces are compared for equality
    Then the comparison is performed by calling the Rust napi constant-time comparison function
    And the Rust function uses subtle::ConstantTimeEq for the byte-level comparison
    And TypeScript receives only a boolean result (match or no match)
    And no byte-by-byte comparison loop exists in TypeScript code

  Scenario: Token validation comparison is performed in Rust napi
    Given a Bearer token is presented in an API request
    And the server retrieves the expected token hash
    When the token hash is compared for validity
    Then the comparison is performed in the Rust napi module using subtle::ConstantTimeEq
    And the comparison time is independent of the position of the first differing byte

  # --- Edge Cases ---

  Scenario: Constant-time comparison timing is verified with dudect methodology
    Given 10000 matching byte pairs are prepared (timing class A)
    And 10000 non-matching byte pairs with differences at varying positions are prepared (timing class B)
    When both classes are interleaved and submitted to the Rust napi comparison function
    And execution times are collected for each class
    Then the Welch t-test statistic between class A and class B is below the threshold (|t| < 4.5)
    And the comparison is deemed constant-time

  Scenario: TypeScript codebase contains no XOR accumulator or byte-by-byte security comparisons
    Given the TypeScript source code is scanned for security comparison patterns
    When the scan searches for XOR accumulator loops, byte-by-byte equality checks on secrets, and timing-sensitive string comparisons
    Then no such patterns are found in the TypeScript codebase
    And all security-sensitive comparisons are delegated to Rust napi functions
    And TypeScript only performs structural routing (e.g., dispatching to the correct handler)

  # --- Error Cases ---

  Scenario: Rust napi comparison function rejects inputs of different lengths
    Given a comparison is requested between a 32-byte value and a 48-byte value
    When the Rust napi constant-time comparison function is called
    Then the function returns false without performing any comparison
    And the rejection is itself constant-time (no early return based on length difference leaking via timing)
    And no panic or exception is thrown — only a false result
```

---

## Feature 5: Global and Per-IP Rate Limiting (RISK 5 — MEDIUM)

```gherkin
Feature: Global and Per-IP Rate Limiting
  As the authentication system
  I want a global rate limit across all clients and a per-IP rate limit at the gateway level
  So that no single source or coordinated attack can exhaust server resources

  Background:
    Given the REST API server is operational
    And the global rate limit is configured at 10000 requests per second
    And the per-IP rate limit is configured at 100 requests per second
    And rate limit counters use a shared store (Redis INCR with TTL)

  # --- Happy Path ---

  Scenario: Requests within global and per-IP limits are processed normally
    Given the current global request rate is 5000 requests per second
    And Alice's IP 10.0.0.1 has sent 20 requests in the current second
    When Alice sends a verification request
    Then the request is processed normally
    And the response does not include rate limiting headers (X-RateLimit-Remaining, Retry-After)

  Scenario: Rate limit headers are included when approaching the limit
    Given Alice's IP 10.0.0.1 has sent 80 requests in the current second (80% of per-IP limit)
    When Alice sends a request
    Then the response includes "X-RateLimit-Limit: 100" header
    And the response includes "X-RateLimit-Remaining: 19" header
    And the request is still processed normally

  # --- Edge Cases ---

  Scenario: Per-IP limit reached but global limit has headroom — IP is throttled
    Given the global request rate is 3000 requests per second (well under limit)
    And IP 10.0.0.99 has sent 100 requests in the current second (at per-IP limit)
    When IP 10.0.0.99 sends another request
    Then the request is rejected with HTTP 429
    And the response includes "Retry-After" header with the seconds until the window resets
    And a "rate_limit_exceeded" event is recorded with source IP and limit type "per_ip"
    And requests from other IPs are not affected

  Scenario: Global limit reached — all new requests are throttled regardless of per-IP headroom
    Given the global request rate reaches 10000 requests per second
    And a new client from IP 10.0.0.200 has sent only 1 request (well under per-IP limit)
    When the new client sends a request
    Then the request is rejected with HTTP 429
    And the response body is a Problem Details object with type "urn:2fapi:error:rate-limit-exceeded"
    And the response includes "Retry-After" header
    And a "global_rate_limit_exceeded" event is recorded

  # --- Error Cases ---

  Scenario: Distributed attack from many IPs triggers global rate limit
    Given an attacker controls 200 different IP addresses
    And each IP sends 60 requests per second (under the per-IP limit of 100)
    And the combined rate is 12000 requests per second (above the global limit of 10000)
    When the global rate counter exceeds 10000
    Then new requests are rejected with HTTP 429 regardless of individual IP usage
    And a "global_rate_limit_exceeded" event is published
    And the event includes the current global rate and the threshold
    And legitimate clients receive Retry-After headers indicating when to retry

  Scenario: Rate limit bypass via IP spoofing is mitigated by gateway-level enforcement
    Given the per-IP rate limit is enforced at the gateway/reverse-proxy level
    And the gateway extracts the client IP from the network connection (not from X-Forwarded-For)
    When an attacker sends requests with spoofed X-Forwarded-For headers
    Then the rate limiter uses the actual connection source IP, not the spoofed header
    And the attacker's requests are correctly attributed to their real IP
    And the per-IP limit is enforced against the real source IP
```

---

## TDD Implementation Order

### Phase 1: Challenge Consumption Atomicity (RISK 1 — CRITICAL)
1. **RED**: Atomic consumption — single request consumes challenge via DB-level atomic operation (DELETE...RETURNING)
2. **RED**: Concurrent consumption — 2 simultaneous requests, exactly 1 succeeds, other gets "challenge_already_consumed"
3. **RED**: High-concurrency consumption — 50 concurrent requests, exactly 1 wins, 49 rejected
4. **RED**: Crash recovery — challenge consumed at DB level survives application crash (no orphaned state)
5. **RED**: No application-level mutex — code review test asserting DB-only atomicity (no in-process lock)
6. **RED**: Consistent error for consumed challenge — error indistinguishable from expired challenge

### Phase 2: Constant-Time Comparisons in Rust (RISK 4 — HIGH)
7. **RED**: Nonce comparison via Rust napi — subtle::ConstantTimeEq, TypeScript receives boolean only
8. **RED**: Token hash comparison via Rust napi — constant-time regardless of differing byte position
9. **RED**: dudect timing validation — 10K samples per class, Welch t-test |t| < 4.5
10. **RED**: TypeScript codebase audit — no XOR accumulators, no byte-by-byte security comparisons
11. **RED**: Different-length inputs — Rust napi returns false in constant time, no panic

### Phase 3: RNG Health Check and Deterministic Nonce Fallback (RISK 3 — HIGH)
12. **RED**: RNG health check — reject all-zeros, all-ones, low entropy (< 4 distinct bytes in 32)
13. **RED**: Hedged nonce derivation — k = H(secret || counter || random), counter ensures uniqueness
14. **RED**: All-zeros RNG fallback — deterministic nonce with counter, "rng_health_failure" event published
15. **RED**: Low-entropy detection — flag output with < 4 distinct byte values, publish "rng_low_entropy" event
16. **RED**: Counter persistence — survives restart, atomic increment, never reuses values
17. **RED**: OsRng unavailable — purely deterministic nonces, "rng_unavailable" event, no failure

### Phase 4: Channel Binding DPoP Fallback (RISK 2 — HIGH)
18. **RED**: DPoP fallback — ephemeral ES256 key, DPoP proof header, token bound to key thumbprint (cnf claim)
19. **RED**: DPoP-bound token usage — subsequent request requires DPoP proof with matching key
20. **RED**: Auto-detect binding mode — TLS Exporter preferred over DPoP when available
21. **RED**: DPoP proof expiry — reject proof with iat beyond clock skew tolerance
22. **RED**: DPoP jti replay — reject reused jti values from replay cache
23. **RED**: Missing both bindings — reject with "channel_binding_required"
24. **RED**: Thumbprint mismatch — Eve's key does not match Alice's token cnf, request rejected

### Phase 5: Global and Per-IP Rate Limiting (RISK 5 — MEDIUM)
25. **RED**: Requests within limits — processed normally, no rate limit headers
26. **RED**: Rate limit headers — included when approaching per-IP threshold (80%+)
27. **RED**: Per-IP limit reached — HTTP 429, Retry-After header, other IPs unaffected
28. **RED**: Global limit reached — HTTP 429 for all clients regardless of per-IP headroom
29. **RED**: Distributed attack — combined rate exceeds global limit, all new requests throttled
30. **RED**: IP spoofing mitigation — gateway uses connection source IP, not X-Forwarded-For
