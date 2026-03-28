# Sprint 9 — REST API

> **Goal**: Expose the 2FApi authentication protocol through a production-ready REST API with strict security, consistent error handling, and developer-friendly conventions.
> **Bounded Context**: API Gateway (infrastructure incoming adapters across all bounded contexts)
> **Scenarios**: 105 | Happy: 18 | Edge: 32 | Error: 55
> **Prerequisites**: Sprints 1-7 (all domain logic, verification, access control, lifecycle, monitoring, and hardening)
> **Key deliverables**: Fastify HTTP server, REST endpoints for enrollment/challenge/verify/access/revocation/rotation, OpenAPI specification, structured error responses (RFC 7807), rate limiting with Retry-After, CORS for browser SDK, request ID tracing, Content-Type enforcement, TLS requirement, body size limits, timing-safe error responses, health check
> **Hypotheses**: H1 (Fastify), H2 (curve25519-dalek v4), H3 (napi-rs + wasm-bindgen), H4 (raw SQL migrations), H5 (Redis standalone + TLS), H6 (admin mTLS), H7 (OpenAPI manual spec)

### Expert Review Summary

> **API/Integration Engineer**: Enforced RFC 7807 Problem Details for all error responses with consistent JSON shape. Added X-Request-Id propagation on every response. Mandated OpenAPI 3.1 spec endpoint. Designed versioned URL paths (/v1/). Added CORS preflight handling for browser SDK integration. Ensured Retry-After header on all 429 responses. Specified content negotiation rules (application/json only, 415 for others).
>
> **Security Researcher**: Enforced indistinguishable error bodies for security-sensitive endpoints (enrollment duplicate, challenge refusal, verification refusal). Mandated timing-safe response delays so all error paths for a given endpoint take equivalent wall-clock time. Required TLS-only (reject plaintext). Required Content-Length enforcement to prevent request smuggling. Ensured no sensitive data (secrets, commitments, proofs) appears in HTTP access logs. Added strict CORS origin allowlist (no wildcard in production). Required Strict-Transport-Security and security headers on all responses.
>
> **IAM Expert**: Enforced mTLS for admin revocation endpoint with client certificate DN in audit log. Ensured token issuance is embedded in the verification response (single round-trip). Mandated Bearer token scheme for resource access. Required that rotation endpoint demands active Bearer authentication. Ensured legacy-free API design (no backward compatibility baggage from day one).

---

## Feature: Cross-Cutting HTTP Conventions

```gherkin
Feature: Cross-Cutting HTTP Conventions
  As a client application developer
  I want consistent, predictable HTTP behavior across all API endpoints
  So that I can build reliable integrations without endpoint-specific quirks

  Background:
    Given the REST API server is operational on HTTPS
    And the base URL path is "/v1"

  # --- Happy Path ---

  Scenario: Every response includes a unique X-Request-Id header
    When any client sends any request to any endpoint
    Then the response includes a "X-Request-Id" header
    And the value is a UUID v4 string
    And if the client provided an "X-Request-Id" header in the request, the response echoes the same value
    And if the client did not provide one, the server generates a new UUID

  Scenario: Health check endpoint returns service status
    When a client sends GET /health
    Then the response status is 200
    And the response body contains:
      | field   | type   | description              |
      | status  | string | "ok" or "degraded"       |
      | version | string | API version (e.g. "1.0") |
    And no authentication is required for this endpoint

  Scenario: OpenAPI specification is publicly accessible
    When a client sends GET /v1/openapi.json
    Then the response status is 200
    And the Content-Type is "application/json"
    And the response body is a valid OpenAPI 3.1 specification
    And no authentication is required for this endpoint

  # --- Edge Cases ---

  Scenario: Request with client-provided X-Request-Id is propagated to audit log
    Given Alice sends a request with header "X-Request-Id: abc-123-def"
    When the request is processed
    Then the audit log entry includes requestId "abc-123-def"
    And the response header "X-Request-Id" is "abc-123-def"

  Scenario: Unversioned path returns 404 with migration hint
    When a client sends POST /clients (without /v1 prefix)
    Then the response status is 404
    And the response body is a Problem Details object with:
      | field  | value                                       |
      | type   | "urn:2fapi:error:not-found"                 |
      | title  | "Not Found"                                 |
      | detail | "Use versioned API paths, e.g. /v1/clients" |

  Scenario: Unknown versioned path returns 404
    When a client sends GET /v1/nonexistent
    Then the response status is 404
    And the response body is a Problem Details object

  Scenario: HEAD request on any endpoint returns headers without body
    When a client sends HEAD /health
    Then the response status is 200
    And the response body is empty
    And all headers are present as if it were a GET request

  Scenario: OPTIONS request returns allowed methods
    When a client sends OPTIONS /v1/clients
    Then the response status is 204
    And the response includes an "Allow" header listing the supported HTTP methods

  # --- Error Cases ---

  Scenario: Wrong Content-Type on POST endpoint returns 415
    When a client sends POST /v1/clients with Content-Type "text/xml"
    Then the response status is 415
    And the response body is a Problem Details object with:
      | field  | value                                               |
      | type   | "urn:2fapi:error:unsupported-media-type"             |
      | title  | "Unsupported Media Type"                            |
      | detail | "Content-Type must be application/json"              |

  Scenario: Missing Content-Type on POST endpoint returns 415
    When a client sends POST /v1/verify without a Content-Type header
    Then the response status is 415
    And the response body is a Problem Details object indicating application/json is required

  Scenario: Oversized request body returns 413
    When a client sends a POST request with a body exceeding 64 KB
    Then the response status is 413
    And the response body is a Problem Details object with:
      | field  | value                                     |
      | type   | "urn:2fapi:error:payload-too-large"       |
      | title  | "Payload Too Large"                       |
      | detail | "Request body must not exceed 65536 bytes"|
    And the connection is closed without reading the full body

  Scenario: Malformed JSON body returns 400
    When a client sends POST /v1/clients with body "not-json{{"
    And Content-Type is "application/json"
    Then the response status is 400
    And the response body is a Problem Details object with:
      | field  | value                              |
      | type   | "urn:2fapi:error:malformed-body"   |
      | title  | "Bad Request"                      |
      | detail | "Request body is not valid JSON"   |

  Scenario: Method not allowed returns 405
    When a client sends DELETE /v1/verify
    Then the response status is 405
    And the response includes an "Allow" header with the supported methods for that path
    And the response body is a Problem Details object

  Scenario: Accept header requesting non-JSON returns 406
    When a client sends a request with Accept "application/xml" to any endpoint
    Then the response status is 406
    And the response body is a Problem Details object indicating only application/json is supported
```

---

## Feature: TLS and Security Headers

```gherkin
Feature: TLS and Security Headers
  As the authentication system
  I want to enforce transport security and include protective HTTP headers
  So that all API communication is confidential and resistant to common web attacks

  Background:
    Given the REST API server is operational

  # --- Happy Path ---

  Scenario: All responses include mandatory security headers
    When any client sends any request to any endpoint
    Then the response includes the following headers:
      | header                    | value                          |
      | Strict-Transport-Security | max-age=63072000; includeSubDomains |
      | X-Content-Type-Options    | nosniff                        |
      | X-Frame-Options           | DENY                           |
      | Cache-Control             | no-store                       |
      | Content-Type              | application/json; charset=utf-8 |
    And the response does NOT include a "Server" header revealing implementation details

  # --- Error Cases ---

  Scenario: Plaintext HTTP request is rejected
    Given the server is configured to accept TLS connections only
    When a client sends a request over plaintext HTTP
    Then the connection is refused at the transport level
    And no response body is returned
    And the rejected connection is recorded in the access log

  Scenario: TLS 1.1 or lower is rejected
    When a client attempts to connect using TLS 1.1
    Then the TLS handshake fails
    And the server only accepts TLS 1.2 or higher

  Scenario: No sensitive data appears in HTTP access logs
    When Alice submits an enrollment request with a commitment and proof of possession
    Then the HTTP access log records the request method, path, status code, and timing
    And the access log does NOT contain the request body
    And the access log does NOT contain any base64-encoded cryptographic material
    And the access log does NOT contain any Authorization header values
```

---

## Feature: CORS for Browser SDK

```gherkin
Feature: CORS for Browser SDK
  As a browser-based client application developer
  I want the API to support CORS with strict origin control
  So that the WASM-based SDK can call the API directly from the browser

  Background:
    Given the REST API server is operational
    And the allowed CORS origins are configured as ["https://app.example.com", "https://dashboard.example.com"]

  # --- Happy Path ---

  Scenario: Preflight request from allowed origin succeeds
    When a browser sends an OPTIONS preflight request to /v1/challenges
    And the request includes header "Origin: https://app.example.com"
    And the request includes header "Access-Control-Request-Method: POST"
    And the request includes header "Access-Control-Request-Headers: Content-Type, X-Request-Id"
    Then the response status is 204
    And the response includes:
      | header                         | value                              |
      | Access-Control-Allow-Origin    | https://app.example.com            |
      | Access-Control-Allow-Methods   | POST, OPTIONS                      |
      | Access-Control-Allow-Headers   | Content-Type, X-Request-Id, Authorization |
      | Access-Control-Max-Age         | 86400                              |
      | Access-Control-Expose-Headers  | X-Request-Id, Retry-After          |
    And the response does NOT include "Access-Control-Allow-Origin: *"

  Scenario: Actual request from allowed origin includes CORS headers
    When a browser sends POST /v1/challenges from origin "https://app.example.com"
    Then the response includes header "Access-Control-Allow-Origin: https://app.example.com"
    And the response includes header "Access-Control-Expose-Headers: X-Request-Id, Retry-After"
    And the response includes header "Vary: Origin"

  # --- Edge Cases ---

  Scenario: Preflight with extra custom header is allowed if configured
    When a browser sends OPTIONS /v1/verify with Access-Control-Request-Headers "Content-Type, X-Request-Id, X-Custom-Trace"
    And "X-Custom-Trace" is not in the allowed headers list
    Then the response status is 204
    And "Access-Control-Allow-Headers" does NOT include "X-Custom-Trace"

  # --- Error Cases ---

  Scenario: Request from disallowed origin receives no CORS headers
    When a browser sends POST /v1/challenges from origin "https://evil.example.com"
    Then the response does NOT include an "Access-Control-Allow-Origin" header
    And the browser enforces the same-origin policy (request blocked client-side)

  Scenario: CORS wildcard is never used in production
    When any request is received from any origin
    Then the response never contains "Access-Control-Allow-Origin: *"
    And origin validation uses an exact match against the configured allowlist
```

---

## Feature: Structured Error Responses (RFC 7807)

```gherkin
Feature: Structured Error Responses
  As a client application developer
  I want all API errors to follow a consistent JSON structure
  So that I can write uniform error handling logic

  Background:
    Given the REST API server is operational

  # --- Happy Path ---

  Scenario: All error responses follow RFC 7807 Problem Details format
    When any request results in an error (4xx or 5xx)
    Then the response Content-Type is "application/problem+json"
    And the response body contains at minimum:
      | field    | type   | description                                      |
      | type     | string | A URI identifying the error type                  |
      | title    | string | A short human-readable summary                    |
      | status   | number | The HTTP status code                               |
      | detail   | string | A human-readable explanation of this specific error |
      | instance | string | The X-Request-Id value for correlation              |
    And the response body does NOT contain stack traces, internal paths, or implementation details

  # --- Edge Cases ---

  Scenario: Error response includes X-Request-Id matching the instance field
    Given Alice sends a request with header "X-Request-Id: req-abc-456"
    When the request results in a 400 error
    Then the Problem Details "instance" field is "req-abc-456"
    And the response header "X-Request-Id" is "req-abc-456"

  Scenario: 500 Internal Server Error uses generic detail
    When an unexpected server error occurs during request processing
    Then the response status is 500
    And the Problem Details body contains:
      | field  | value                               |
      | type   | "urn:2fapi:error:internal"          |
      | title  | "Internal Server Error"             |
      | detail | "An unexpected error occurred"      |
    And the detail does NOT reveal the nature of the internal failure
    And the actual error details are logged server-side with the X-Request-Id for correlation
```

---

## Feature: Client Enrollment Endpoint

```gherkin
Feature: Client Enrollment Endpoint
  As a client application developer
  I want to register my application via POST /v1/clients
  So that I can enroll my Pedersen commitment for future zero-knowledge authentication

  Background:
    Given the REST API server is operational
    And the public parameters (generators g and h) are published

  # --- Happy Path ---

  Scenario: Successful enrollment returns 201 Created
    Given Alice has prepared a valid enrollment payload:
      | field              | value                        |
      | clientIdentifier   | "alice-payment-service"      |
      | commitment         | <valid base64 of 32 bytes>   |
      | proofOfPossession  | <valid base64 of proof>      |
    When Alice sends POST /v1/clients with Content-Type "application/json"
    Then the response status is 201
    And the response body contains:
      | field            | type   | description                |
      | referenceId      | string | Opaque enrollment receipt  |
      | clientIdentifier | string | "alice-payment-service"    |
    And the response includes header "Location: /v1/clients/{referenceId}"
    And the response includes header "X-Request-Id"
    And a "ClientEnrolled" domain event is published

  # --- Edge Cases ---

  Scenario: Idempotent retry with same identifier and same commitment returns original receipt
    Given Alice has already been enrolled with identifier "alice-payment-service" and commitment C
    When Alice sends the same POST /v1/clients with the same identifier and same commitment
    Then the response status is 201
    And the response body is identical to the original enrollment receipt

  Scenario: Extra fields in enrollment request body are ignored
    Given Alice sends POST /v1/clients with an additional field "extraField": "value"
    When the request is processed
    Then the unexpected field is silently ignored
    And the enrollment proceeds based on recognized fields only

  Scenario: Enrollment with minimum-length client identifier succeeds
    Given Alice sends POST /v1/clients with clientIdentifier "a" (1 character)
    And commitment and proofOfPossession are valid
    When the request is processed
    Then the response status is 201

  Scenario: Enrollment with maximum-length client identifier succeeds
    Given Alice sends POST /v1/clients with clientIdentifier of exactly 128 characters
    And commitment and proofOfPossession are valid
    When the request is processed
    Then the response status is 201

  # --- Error Cases ---

  Scenario: Missing clientIdentifier returns 400
    Given Alice sends POST /v1/clients without the "clientIdentifier" field
    When the request is processed
    Then the response status is 400
    And the Problem Details body contains:
      | field  | value                                     |
      | type   | "urn:2fapi:error:validation"              |
      | title  | "Bad Request"                             |
      | detail | "Missing required field: clientIdentifier" |

  Scenario: Missing commitment returns 400
    Given Alice sends POST /v1/clients without the "commitment" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates commitment is required

  Scenario: Missing proofOfPossession returns 400
    Given Alice sends POST /v1/clients without the "proofOfPossession" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates proofOfPossession is required

  Scenario: Malformed base64 in commitment returns 400
    Given Alice sends POST /v1/clients with commitment "not-valid-base64!!!"
    When the request is processed
    Then the response status is 400
    And the Problem Details body contains:
      | field  | value                                           |
      | type   | "urn:2fapi:error:validation"                    |
      | detail | "Invalid base64 encoding in field: commitment"  |

  Scenario: Malformed base64 in proofOfPossession returns 400
    Given Alice sends POST /v1/clients with proofOfPossession "also-not-base64!!!"
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates invalid base64 encoding in proofOfPossession

  Scenario: Client identifier exceeding maximum length returns 400
    Given Alice sends POST /v1/clients with clientIdentifier of 129 characters
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates clientIdentifier exceeds maximum length

  Scenario: Empty client identifier returns 400
    Given Alice sends POST /v1/clients with clientIdentifier ""
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates clientIdentifier must not be empty

  Scenario: Client identifier with invalid characters returns 400
    Given Alice sends POST /v1/clients with clientIdentifier containing control characters or spaces
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates clientIdentifier contains invalid characters

  Scenario: Duplicate client identifier with different commitment returns indistinguishable error
    Given a client with identifier "alice-payment-service" already exists with a different commitment
    When Alice sends POST /v1/clients with identifier "alice-payment-service" and a new commitment
    Then the response status is 409
    And the Problem Details body is IDENTICAL in structure and field content to:
      | field  | value                               |
      | type   | "urn:2fapi:error:enrollment-refused" |
      | title  | "Enrollment Refused"                 |
      | detail | "Enrollment could not be completed"  |
    And this response body is indistinguishable from an invalid proof of possession refusal
    And the response timing is indistinguishable from other enrollment failures

  Scenario: Invalid proof of possession returns indistinguishable error
    Given Alice sends POST /v1/clients with a valid commitment but an invalid proof of possession
    When the request is processed
    Then the response status is 409
    And the Problem Details body is IDENTICAL to the duplicate identifier error response
    And the response timing is indistinguishable from a duplicate identifier refusal

  Scenario: Rate limiting on enrollment returns 429 with Retry-After
    Given Alice has exceeded the enrollment rate limit from her source
    When Alice sends POST /v1/clients
    Then the response status is 429
    And the response includes header "Retry-After" with a value in seconds
    And the Problem Details body contains:
      | field  | value                             |
      | type   | "urn:2fapi:error:rate-limited"    |
      | title  | "Too Many Requests"               |
      | detail | "Rate limit exceeded, retry later" |
```

---

## Feature: Challenge Request Endpoint

```gherkin
Feature: Challenge Request Endpoint
  As a client application
  I want to request an authentication challenge via POST /v1/challenges
  So that I can obtain a fresh nonce to bind my zero-knowledge proof

  Background:
    Given the REST API server is operational
    And Alice is registered with identifier "alice-payment-service" and status "active"

  # --- Happy Path ---

  Scenario: Successful challenge issuance returns 200 OK
    Given Alice has prepared a valid challenge request payload:
      | field           | value                        |
      | clientIdentifier | "alice-payment-service"     |
      | credential       | <valid base64 credential>   |
      | channelBinding   | <valid base64 TLS binding>  |
    When Alice sends POST /v1/challenges with Content-Type "application/json"
    Then the response status is 200
    And the response body contains:
      | field          | type   | description                                   |
      | challengeId    | string | Opaque challenge identifier                   |
      | nonce          | string | Base64-encoded fresh nonce                     |
      | channelBinding | string | Base64-encoded server channel binding response |
      | expiresAt      | string | ISO 8601 timestamp of challenge expiry         |
    And the response includes header "X-Request-Id"
    And a "ChallengeIssued" domain event is published

  Scenario: Successful challenge includes protocol version in response
    Given Alice sends POST /v1/challenges with optional field protocolVersion "1.0"
    When the challenge is issued
    Then the response body additionally contains:
      | field           | type   | value |
      | protocolVersion | string | "1.0" |

  # --- Edge Cases ---

  Scenario: New challenge invalidates previous pending challenge
    Given Alice already has a pending challenge
    When Alice sends POST /v1/challenges again with a valid credential
    Then the response status is 200
    And a new challenge is issued
    And the previous pending challenge is invalidated

  Scenario: Challenge request without optional protocolVersion defaults to "1.0"
    Given Alice sends POST /v1/challenges without the "protocolVersion" field
    When the challenge is issued
    Then the challenge is processed using protocol version "1.0"
    And the response includes protocolVersion "1.0"

  # --- Error Cases ---

  Scenario: Missing clientIdentifier returns 400
    Given Alice sends POST /v1/challenges without the "clientIdentifier" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates clientIdentifier is required

  Scenario: Missing credential returns 400
    Given Alice sends POST /v1/challenges without the "credential" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates credential is required

  Scenario: Missing channelBinding returns 400
    Given Alice sends POST /v1/challenges without the "channelBinding" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates channelBinding is required

  Scenario: Malformed base64 in credential returns 400
    Given Alice sends POST /v1/challenges with credential "not-base64!!!"
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates invalid base64 encoding in credential

  Scenario: Invalid credential returns indistinguishable 401
    Given Alice sends POST /v1/challenges with an incorrect credential
    When the request is processed
    Then the response status is 401
    And the Problem Details body contains:
      | field  | value                                     |
      | type   | "urn:2fapi:error:challenge-refused"        |
      | title  | "Unauthorized"                             |
      | detail | "Challenge request could not be completed" |
    And this response is indistinguishable from an unknown client refusal
    And the response timing is indistinguishable from other challenge refusals

  Scenario: Unknown client identifier returns indistinguishable 401
    Given Eve sends POST /v1/challenges with clientIdentifier "unknown-service"
    When the request is processed
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid credential error response
    And the response timing is indistinguishable from an invalid credential refusal

  Scenario: Revoked client returns indistinguishable 401
    Given Alice's client status is "revoked"
    When Alice sends POST /v1/challenges
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the unknown client error response
    And the response timing is indistinguishable

  Scenario: Locked-out client returns indistinguishable 401
    Given Alice has been locked out due to failed authentication attempts
    When Alice sends POST /v1/challenges
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the unknown client error response
    And the response timing is indistinguishable

  Scenario: Unsupported protocol version returns 400 with supported list
    Given Alice sends POST /v1/challenges with protocolVersion "0.1-deprecated"
    When the request is processed
    Then the response status is 400
    And the Problem Details body contains:
      | field  | value                                              |
      | type   | "urn:2fapi:error:unsupported-version"               |
      | title  | "Bad Request"                                       |
      | detail | "Protocol version '0.1-deprecated' is not supported"|
    And the response body includes an additional field "supportedVersions": ["1.0"]

  Scenario: Rate limiting on challenge requests returns 429
    Given Alice has exceeded the challenge request rate limit
    When Alice sends POST /v1/challenges
    Then the response status is 429
    And the response includes header "Retry-After" with a value in seconds
    And the Problem Details body indicates rate limiting
```

---

## Feature: Proof Verification Endpoint

```gherkin
Feature: Proof Verification Endpoint
  As a client application
  I want to submit my zero-knowledge proof via POST /v1/verify
  So that I can authenticate and receive an access token in a single round-trip

  Background:
    Given the REST API server is operational
    And Alice is registered with identifier "alice-payment-service" and an active commitment
    And Alice has a valid pending challenge with challengeId "ch_42"

  # --- Happy Path ---

  Scenario: Successful verification returns 200 OK with access token
    Given Alice has prepared a valid verification payload:
      | field                | value                          |
      | clientIdentifier     | "alice-payment-service"        |
      | challengeId          | "ch_42"                        |
      | proof                | <valid base64 proof>           |
      | channelBinding       | <valid base64 TLS binding>     |
      | domainSeparationTag  | "2FApi-v1.0-Sigma"             |
    When Alice sends POST /v1/verify with Content-Type "application/json"
    Then the response status is 200
    And the response body contains:
      | field       | type   | description                           |
      | accessToken | string | Short-lived Bearer token               |
      | tokenType   | string | "Bearer"                               |
      | expiresAt   | string | ISO 8601 timestamp of token expiry     |
      | expiresIn   | number | Seconds until token expires (e.g. 900) |
    And the response includes header "X-Request-Id"
    And a "ProofVerified" domain event is published
    And a "TokenIssued" domain event is published
    And the used challenge is consumed

  # --- Edge Cases ---

  Scenario: Verification response never includes the proof or secret material
    When Alice receives a successful verification response
    Then the response body does NOT contain the submitted proof
    And the response body does NOT contain any commitment value
    And the response body does NOT contain the nonce or challenge details

  Scenario: Verification at exact challenge expiry boundary returns 401
    Given Alice's challenge was issued exactly 120 seconds ago with 2-minute TTL
    When Alice sends POST /v1/verify with a valid proof
    Then the response status is 401
    And the response indicates the challenge has expired (indistinguishable from other failures)

  # --- Error Cases ---

  Scenario: Missing clientIdentifier returns 400
    Given Alice sends POST /v1/verify without the "clientIdentifier" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates clientIdentifier is required

  Scenario: Missing challengeId returns 400
    Given Alice sends POST /v1/verify without the "challengeId" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates challengeId is required

  Scenario: Missing proof returns 400
    Given Alice sends POST /v1/verify without the "proof" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates proof is required

  Scenario: Missing channelBinding returns 400
    Given Alice sends POST /v1/verify without the "channelBinding" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates channelBinding is required

  Scenario: Missing domainSeparationTag returns 400
    Given Alice sends POST /v1/verify without the "domainSeparationTag" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates domainSeparationTag is required

  Scenario: Malformed base64 in proof returns 400
    Given Alice sends POST /v1/verify with proof "not-base64!!!"
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates invalid base64 encoding in proof

  Scenario: Invalid proof returns indistinguishable 401
    Given Alice sends POST /v1/verify with an incorrect proof
    When the request is processed
    Then the response status is 401
    And the Problem Details body contains:
      | field  | value                                         |
      | type   | "urn:2fapi:error:verification-refused"         |
      | title  | "Unauthorized"                                 |
      | detail | "Verification could not be completed"          |
    And this response is indistinguishable from an unknown client refusal
    And the response timing is indistinguishable from other verification failures

  Scenario: Unknown client identifier returns indistinguishable 401
    Given Eve sends POST /v1/verify with clientIdentifier "unknown-service"
    When the request is processed
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid proof error response
    And the response timing is indistinguishable

  Scenario: Expired challenge returns indistinguishable 401
    Given Alice's challenge expired 60 seconds ago
    When Alice sends POST /v1/verify with a proof bound to the expired challenge
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid proof error response
    And the response timing is indistinguishable

  Scenario: Consumed (replayed) challenge returns indistinguishable 401
    Given Alice's challenge "ch_42" was already used in a successful verification
    When Eve sends POST /v1/verify with a proof bound to "ch_42"
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid proof error response
    And the response timing is indistinguishable

  Scenario: Wrong channel binding returns indistinguishable 401
    Given Alice sends POST /v1/verify with valid proof but mismatched channel binding
    When the request is processed
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid proof error response
    And the response timing is indistinguishable

  Scenario: Wrong domain separation tag returns indistinguishable 401
    Given Alice sends POST /v1/verify with domainSeparationTag "OtherProtocol-v1.0"
    When the request is processed
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid proof error response

  Scenario: Rate limiting on verification returns 429
    Given Eve has exceeded the verification rate limit
    When Eve sends POST /v1/verify
    Then the response status is 429
    And the response includes header "Retry-After" with a value in seconds
    And the Problem Details body indicates rate limiting
```

---

## Feature: Resource Access Endpoint

```gherkin
Feature: Resource Access Endpoint
  As a client application
  I want to access protected resources via GET /v1/resources/{resourceId}
  So that I can perform authorized operations after authentication

  Background:
    Given the REST API server is operational
    And Alice holds a valid Bearer access token with the correct audience

  # --- Happy Path ---

  Scenario: Authenticated request with valid Bearer token returns resource
    When Alice sends GET /v1/resources/payment-config with header "Authorization: Bearer <valid_token>"
    Then the response status is 200
    And the response body contains the requested resource data
    And the response includes header "X-Request-Id"

  Scenario: Bearer token scheme is case-insensitive per RFC 6750
    When Alice sends GET /v1/resources/payment-config with header "Authorization: bearer <valid_token>"
    Then the response status is 200
    And the token is accepted regardless of "Bearer" vs "bearer" casing

  # --- Edge Cases ---

  Scenario: Multiple sequential requests with same valid token all succeed
    Given Alice's token is valid for another 10 minutes
    When Alice sends 50 GET requests to /v1/resources/payment-config
    Then all 50 responses have status 200

  Scenario: Token used 1 second before expiry succeeds
    Given Alice's token expires in 1 second
    When Alice sends GET /v1/resources/payment-config
    Then the response status is 200

  # --- Error Cases ---

  Scenario: Request without Authorization header returns 401
    When Eve sends GET /v1/resources/payment-config without an Authorization header
    Then the response status is 401
    And the response includes header "WWW-Authenticate: Bearer realm=\"2fapi\""
    And the Problem Details body contains:
      | field  | value                                   |
      | type   | "urn:2fapi:error:unauthorized"          |
      | title  | "Unauthorized"                          |
      | detail | "Bearer token required"                 |

  Scenario: Malformed Authorization header returns 401
    When Eve sends GET /v1/resources/payment-config with header "Authorization: NotBearer xyz"
    Then the response status is 401
    And the response includes header "WWW-Authenticate: Bearer realm=\"2fapi\""
    And the Problem Details detail indicates invalid authorization scheme

  Scenario: Expired token returns 401
    Given Alice's token expired 60 seconds ago
    When Alice sends GET /v1/resources/payment-config with the expired token
    Then the response status is 401
    And the Problem Details body contains:
      | field  | value                                |
      | type   | "urn:2fapi:error:token-expired"      |
      | title  | "Unauthorized"                       |
      | detail | "Access token has expired"           |
    And the response includes header "WWW-Authenticate: Bearer realm=\"2fapi\", error=\"invalid_token\""

  Scenario: Token with wrong audience returns 403
    Given Alice holds a valid token with audience "payment-api"
    When Alice sends GET /v1/resources/user-config (protected by service "user-management-api")
    Then the response status is 403
    And the Problem Details body contains:
      | field  | value                                              |
      | type   | "urn:2fapi:error:forbidden"                        |
      | title  | "Forbidden"                                         |
      | detail | "Token audience does not match the target resource" |

  Scenario: Forged token returns 401 with constant-time timing
    When Eve sends GET /v1/resources/payment-config with a fabricated token
    Then the response status is 401
    And the response timing is indistinguishable from an expired token rejection

  Scenario: Revoked client's token returns 403
    Given Alice's client was revoked after token issuance
    When Alice sends GET /v1/resources/payment-config with her pre-revocation token
    Then the response status is 403
    And the Problem Details body contains:
      | field  | value                                   |
      | type   | "urn:2fapi:error:forbidden"             |
      | title  | "Forbidden"                              |
      | detail | "Access denied"                          |
    And the response is indistinguishable from a wrong-audience rejection

  Scenario: Token presented on different connection (channel binding mismatch) returns 401
    Given Alice received her token bound to connection "conn_A"
    When Alice presents the token on connection "conn_B"
    Then the response status is 401
    And the response is indistinguishable from an expired token rejection
```

---

## Feature: Client Revocation Endpoint

```gherkin
Feature: Client Revocation Endpoint
  As a server administrator
  I want to revoke a client via DELETE /v1/clients/{clientId}
  So that the client can no longer authenticate

  Background:
    Given the REST API server is operational
    And administrator Bob is authenticated via mTLS with client certificate DN "CN=bob-admin,O=2fapi"

  # --- Happy Path ---

  Scenario: Successful revocation returns 204 No Content
    Given client "alice-payment-service" is registered with status "active"
    When Bob sends DELETE /v1/clients/alice-payment-service with a valid mTLS client certificate
    Then the response status is 204
    And the response body is empty
    And a "ClientRevoked" domain event is published
    And the audit log records the revocation with administrator identity "CN=bob-admin,O=2fapi"
    And Alice's active tokens and pending challenges are invalidated

  # --- Edge Cases ---

  Scenario: Revocation of already revoked client returns 204 (idempotent)
    Given client "alice-payment-service" is already revoked
    When Bob sends DELETE /v1/clients/alice-payment-service
    Then the response status is 204
    And the response body is empty
    And the response timing is indistinguishable from a first-time revocation

  Scenario: Revocation of unknown client returns 204 (indistinguishable)
    When Bob sends DELETE /v1/clients/nonexistent-service
    Then the response status is 204
    And the response body is empty
    And the response timing is indistinguishable from a real revocation
    And no state change occurs

  # --- Error Cases ---

  Scenario: Revocation without mTLS client certificate returns 401
    When an unauthenticated caller sends DELETE /v1/clients/alice-payment-service without a client certificate
    Then the response status is 401
    And the Problem Details body contains:
      | field  | value                                       |
      | type   | "urn:2fapi:error:unauthorized"              |
      | title  | "Unauthorized"                               |
      | detail | "Client certificate required for admin operations" |

  Scenario: Revocation with non-admin certificate returns 403
    Given Eve presents a valid mTLS certificate but without the admin role
    When Eve sends DELETE /v1/clients/alice-payment-service
    Then the response status is 403
    And the Problem Details body contains:
      | field  | value                                          |
      | type   | "urn:2fapi:error:forbidden"                    |
      | title  | "Forbidden"                                     |
      | detail | "Administrator privileges required"             |
    And the attempt is recorded in the audit log as unauthorized revocation attempt

  Scenario: Revocation with expired client certificate returns 401
    Given Bob presents an expired mTLS client certificate
    When Bob sends DELETE /v1/clients/alice-payment-service
    Then the response status is 401
    And the TLS handshake may fail, or the server rejects the expired certificate at the application level

  Scenario: Revocation via non-DELETE method returns 405
    When Bob sends POST /v1/clients/alice-payment-service
    Then the response status is 405
    And the response includes header "Allow: DELETE"
```

---

## Feature: Commitment Rotation Endpoint

```gherkin
Feature: Commitment Rotation Endpoint
  As a client application developer
  I want to rotate my commitment via PUT /v1/clients/{clientId}/commitment
  So that I can update my secret without service interruption

  Background:
    Given the REST API server is operational
    And Alice is registered with identifier "alice-payment-service" and an active commitment
    And Alice holds a valid Bearer token authenticating her as "alice-payment-service"

  # --- Happy Path ---

  Scenario: Successful commitment rotation returns 200 OK
    Given Alice has prepared a valid rotation payload:
      | field              | value                                   |
      | currentProof       | <valid base64 proof of current opening>  |
      | newCommitment      | <valid base64 of new 32-byte commitment> |
      | newCommitmentProof | <valid base64 proof of possession>        |
    When Alice sends PUT /v1/clients/alice-payment-service/commitment with Content-Type "application/json" and her Bearer token
    Then the response status is 200
    And the response body contains:
      | field     | type   | description                        |
      | rotatedAt | string | ISO 8601 timestamp of rotation     |
    And the response includes header "X-Request-Id"
    And a "CommitmentRotated" domain event is published
    And all active tokens issued under the old commitment are invalidated

  # --- Edge Cases ---

  Scenario: Rotation by different client for same clientId is forbidden
    Given Bob holds a valid Bearer token for "bob-billing-service"
    When Bob sends PUT /v1/clients/alice-payment-service/commitment with his token
    Then the response status is 403
    And the Problem Details detail indicates insufficient privileges

  Scenario: Rotation request with extra fields are ignored
    Given Alice sends a rotation request with an additional field "notes": "rotating for compliance"
    When the request is processed
    Then the extra field is silently ignored
    And the rotation proceeds normally

  # --- Error Cases ---

  Scenario: Rotation without Bearer token returns 401
    When Alice sends PUT /v1/clients/alice-payment-service/commitment without an Authorization header
    Then the response status is 401
    And the response includes header "WWW-Authenticate: Bearer realm=\"2fapi\""

  Scenario: Missing currentProof returns 400
    Given Alice sends a rotation request without the "currentProof" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates currentProof is required

  Scenario: Missing newCommitment returns 400
    Given Alice sends a rotation request without the "newCommitment" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates newCommitment is required

  Scenario: Missing newCommitmentProof returns 400
    Given Alice sends a rotation request without the "newCommitmentProof" field
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates newCommitmentProof is required

  Scenario: Malformed base64 in newCommitment returns 400
    Given Alice sends a rotation request with newCommitment "not-base64!!!"
    When the request is processed
    Then the response status is 400
    And the Problem Details detail indicates invalid base64 encoding in newCommitment

  Scenario: Invalid currentProof returns 401
    Given Alice sends a rotation request with an incorrect currentProof
    When the request is processed
    Then the response status is 401
    And the Problem Details body contains:
      | field  | value                                    |
      | type   | "urn:2fapi:error:rotation-refused"       |
      | title  | "Unauthorized"                            |
      | detail | "Rotation could not be completed"        |
    And the failed attempt counts toward the lockout threshold

  Scenario: New commitment equal to current commitment returns 409
    Given Alice sends a rotation request where newCommitment equals the current commitment
    When the request is processed
    Then the response status is 409
    And the Problem Details detail indicates the new commitment must differ from the current one

  Scenario: Rate limiting on rotation returns 429
    Given Alice has exceeded the rotation rate limit
    When Alice sends PUT /v1/clients/alice-payment-service/commitment
    Then the response status is 429
    And the response includes header "Retry-After" with a value in seconds

  Scenario: Service at write capacity returns 503
    Given the registry is unable to accept write operations
    When Alice sends PUT /v1/clients/alice-payment-service/commitment
    Then the response status is 503
    And the response includes header "Retry-After" with a suggested backoff in seconds
    And the Problem Details body contains:
      | field  | value                                           |
      | type   | "urn:2fapi:error:service-unavailable"            |
      | title  | "Service Unavailable"                             |
      | detail | "Service temporarily at capacity, retry later"   |

  Scenario: Rotation for revoked client returns indistinguishable 401
    Given Alice's client status is "revoked"
    When Alice sends PUT /v1/clients/alice-payment-service/commitment
    Then the response status is 401
    And the Problem Details body is IDENTICAL to the invalid currentProof error response
    And the response timing is indistinguishable
```

---

## Feature: Rate Limiting

```gherkin
Feature: Rate Limiting
  As the authentication system
  I want to enforce rate limits on all endpoints
  So that abuse and brute-force attacks are mitigated

  Background:
    Given the REST API server is operational
    And rate limiting is configured per-endpoint, per-client, and per-source-IP

  # --- Happy Path ---

  Scenario: Requests within rate limit are served normally
    Given Alice sends 10 POST /v1/challenges within 60 seconds
    And the rate limit is 20 requests per minute per client
    When all 10 requests are processed
    Then all 10 receive normal responses (no 429)
    And each response includes rate limit headers:
      | header              | description                              |
      | X-RateLimit-Limit   | Maximum requests in the current window   |
      | X-RateLimit-Remaining | Remaining requests in the current window |
      | X-RateLimit-Reset   | Unix timestamp when the window resets     |

  # --- Edge Cases ---

  Scenario: Rate limit headers are present on every response including errors
    When Alice sends POST /v1/verify with a malformed body
    Then the response status is 400
    And the response includes X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset headers

  Scenario: Rate limit window resets after the configured interval
    Given Alice used all 20 requests in the current 60-second window
    When the window resets after 60 seconds
    And Alice sends POST /v1/challenges
    Then the response status is 200 (not 429)
    And X-RateLimit-Remaining reflects the fresh window

  # --- Error Cases ---

  Scenario: Exceeding per-source-IP rate limit returns 429
    Given a single source IP has sent 100 requests across all endpoints within 10 seconds
    When another request is sent from that IP
    Then the response status is 429
    And the response includes header "Retry-After" with a value in seconds
    And the Problem Details body indicates rate limiting
    And the response does NOT reveal which rate limit dimension was exceeded

  Scenario: Exceeding per-client rate limit returns 429 regardless of source IP
    Given Eve distributes 50 requests for client "alice-payment-service" across 10 different IPs
    And the per-client rate limit is 30 requests per minute
    When the 31st request arrives
    Then the response status is 429
    And the Retry-After header is present

  Scenario: Rate limited response does not consume expensive server resources
    When a rate-limited request is detected
    Then the 429 response is returned before any domain logic is invoked
    And no database lookup, cryptographic operation, or event publication occurs
```

---

## Feature: Timing-Safe Error Responses

```gherkin
Feature: Timing-Safe Error Responses
  As the authentication system
  I want all error responses for security-sensitive endpoints to take equivalent time
  So that timing attacks cannot distinguish between different failure reasons

  Background:
    Given the REST API server is operational

  # --- Edge Cases ---

  Scenario: Enrollment errors are timing-indistinguishable
    Given the following enrollment error cases:
      | case                       | description                     |
      | duplicate_identifier       | Existing client, different commitment |
      | invalid_proof_of_possession | Valid commitment, bad proof     |
      | stolen_commitment          | Existing commitment, bad proof  |
    When 1000 requests of each case are measured
    Then the response time distributions are statistically indistinguishable (Welch t-test |t| < 4.5)

  Scenario: Challenge refusal errors are timing-indistinguishable
    Given the following challenge error cases:
      | case               | description              |
      | unknown_client     | Non-existent identifier  |
      | invalid_credential | Wrong credential         |
      | revoked_client     | Client is revoked        |
      | locked_out_client  | Client is locked out     |
    When 1000 requests of each case are measured
    Then the response time distributions are statistically indistinguishable (Welch t-test |t| < 4.5)

  Scenario: Verification refusal errors are timing-indistinguishable
    Given the following verification error cases:
      | case                  | description                     |
      | unknown_client        | Non-existent identifier         |
      | invalid_proof         | Wrong proof response values     |
      | expired_challenge     | Challenge past TTL              |
      | consumed_challenge    | Already-used challenge          |
      | wrong_channel_binding | Mismatched channel binding      |
      | wrong_domain_tag      | Wrong domain separation tag     |
    When 1000 requests of each case are measured
    Then the response time distributions are statistically indistinguishable (Welch t-test |t| < 4.5)

  Scenario: Revocation responses are timing-indistinguishable
    Given the following revocation cases:
      | case              | description              |
      | active_client     | First-time revocation    |
      | already_revoked   | Idempotent revocation    |
      | unknown_client    | Non-existent client      |
    When 1000 requests of each case are measured
    Then the response time distributions are statistically indistinguishable (Welch t-test |t| < 4.5)
```

---

## Feature: API Versioning

```gherkin
Feature: API Versioning
  As the API maintainer
  I want to version the API via URL path prefix
  So that breaking changes can be introduced without disrupting existing integrations

  Background:
    Given the REST API server is operational

  # --- Happy Path ---

  Scenario: All endpoints are served under /v1 prefix
    When a client sends POST /v1/clients with a valid payload
    Then the response status is 201
    And the endpoint is reachable at the versioned path

  # --- Edge Cases ---

  Scenario: Future /v2 prefix is not yet available
    When a client sends POST /v2/clients
    Then the response status is 404
    And the Problem Details body contains:
      | field  | value                                            |
      | type   | "urn:2fapi:error:not-found"                      |
      | detail | "API version 'v2' is not available"               |

  # --- Error Cases ---

  Scenario: Request to root path returns 404 with versioning hint
    When a client sends GET /
    Then the response status is 404
    And the Problem Details detail suggests using versioned paths (e.g., /v1/)

  Scenario: Request with version in header instead of path returns 404
    When a client sends POST /clients with header "Accept-Version: 1"
    Then the response status is 404
    And the Problem Details detail indicates URL-path versioning is required
```

---

## TDD Implementation Order

### Phase 1: HTTP Server Foundation (Fastify)
1. **RED**: Health check GET /health returns 200 with status and version
2. **RED**: OpenAPI spec GET /v1/openapi.json returns valid OpenAPI 3.1 document
3. **RED**: X-Request-Id header generated on every response (UUID v4)
4. **RED**: X-Request-Id echoed from client request if provided
5. **RED**: Security headers on all responses (HSTS, X-Content-Type-Options, X-Frame-Options, Cache-Control, no Server header)
6. **RED**: TLS-only enforcement (reject plaintext, reject TLS < 1.2)

### Phase 2: Request Validation & Error Handling
7. **RED**: RFC 7807 Problem Details format for all error responses (application/problem+json)
8. **RED**: Wrong Content-Type on POST returns 415
9. **RED**: Missing Content-Type on POST returns 415
10. **RED**: Oversized request body returns 413 (64 KB limit)
11. **RED**: Malformed JSON body returns 400
12. **RED**: Method not allowed returns 405 with Allow header
13. **RED**: Accept header requesting non-JSON returns 406
14. **RED**: Unknown path returns 404
15. **RED**: Unversioned path returns 404 with migration hint
16. **RED**: 500 errors use generic detail, log actual error with X-Request-Id

### Phase 3: Rate Limiting
17. **RED**: Rate limit headers on all responses (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
18. **RED**: Per-source-IP rate limit returns 429 with Retry-After
19. **RED**: Per-client rate limit returns 429 with Retry-After
20. **RED**: Rate-limited response short-circuits before domain logic
21. **RED**: Rate limit window reset after configured interval

### Phase 4: CORS
22. **RED**: OPTIONS preflight from allowed origin returns 204 with CORS headers
23. **RED**: Actual request from allowed origin includes Access-Control-Allow-Origin
24. **RED**: Request from disallowed origin gets no CORS headers
25. **RED**: CORS wildcard never used (exact origin match from allowlist)
26. **RED**: Access-Control-Expose-Headers includes X-Request-Id and Retry-After

### Phase 5: Client Enrollment Endpoint (POST /v1/clients)
27. **RED**: Valid enrollment request returns 201 with referenceId and clientIdentifier
28. **RED**: Response includes Location header
29. **RED**: Missing clientIdentifier returns 400
30. **RED**: Missing commitment returns 400
31. **RED**: Missing proofOfPossession returns 400
32. **RED**: Malformed base64 in commitment returns 400
33. **RED**: Malformed base64 in proofOfPossession returns 400
34. **RED**: Empty / too-long / invalid-chars clientIdentifier returns 400
35. **RED**: Duplicate identifier returns 409, indistinguishable body from invalid proof
36. **RED**: Invalid proof of possession returns 409, indistinguishable body from duplicate
37. **RED**: Idempotent retry (same identifier + same commitment) returns original receipt
38. **RED**: Extra fields in request body are ignored
39. **RED**: Rate limiting returns 429 with Retry-After

### Phase 6: Challenge Request Endpoint (POST /v1/challenges)
40. **RED**: Valid challenge request returns 200 with challengeId, nonce, channelBinding, expiresAt
41. **RED**: Missing clientIdentifier / credential / channelBinding returns 400
42. **RED**: Malformed base64 in credential returns 400
43. **RED**: Invalid credential returns 401, indistinguishable from unknown client
44. **RED**: Unknown client returns 401, indistinguishable from invalid credential
45. **RED**: Revoked client returns 401, indistinguishable
46. **RED**: Locked-out client returns 401, indistinguishable
47. **RED**: Unsupported protocol version returns 400 with supportedVersions list
48. **RED**: New challenge invalidates previous pending challenge
49. **RED**: Rate limiting returns 429 with Retry-After

### Phase 7: Proof Verification Endpoint (POST /v1/verify)
50. **RED**: Valid proof returns 200 with accessToken, tokenType, expiresAt, expiresIn
51. **RED**: Missing clientIdentifier / challengeId / proof / channelBinding / domainSeparationTag returns 400
52. **RED**: Malformed base64 in proof returns 400
53. **RED**: Invalid proof returns 401, indistinguishable from unknown client
54. **RED**: Unknown client returns 401, indistinguishable
55. **RED**: Expired challenge returns 401, indistinguishable
56. **RED**: Consumed challenge returns 401, indistinguishable
57. **RED**: Wrong channel binding returns 401, indistinguishable
58. **RED**: Wrong domain separation tag returns 401, indistinguishable
59. **RED**: Challenge at exact expiry boundary returns 401
60. **RED**: Response never includes proof or secret material
61. **RED**: Rate limiting returns 429 with Retry-After

### Phase 8: Resource Access Endpoint (GET /v1/resources/{resourceId})
62. **RED**: Valid Bearer token returns 200 with resource data
63. **RED**: No Authorization header returns 401 with WWW-Authenticate
64. **RED**: Malformed Authorization header returns 401
65. **RED**: Expired token returns 401
66. **RED**: Wrong audience returns 403
67. **RED**: Forged token returns 401, constant-time timing
68. **RED**: Revoked client's token returns 403, indistinguishable from wrong audience
69. **RED**: Channel binding mismatch returns 401, indistinguishable from expired token
70. **RED**: Multiple sequential requests with same valid token all succeed
71. **RED**: Bearer scheme is case-insensitive

### Phase 9: Client Revocation Endpoint (DELETE /v1/clients/{clientId})
72. **RED**: Valid mTLS admin revocation returns 204 No Content
73. **RED**: Already-revoked client returns 204 (idempotent, indistinguishable timing)
74. **RED**: Unknown client returns 204 (indistinguishable timing)
75. **RED**: No client certificate returns 401
76. **RED**: Non-admin certificate returns 403
77. **RED**: Expired certificate returns 401
78. **RED**: Audit log records administrator DN from client certificate
79. **RED**: Wrong HTTP method returns 405 with Allow header

### Phase 10: Commitment Rotation Endpoint (PUT /v1/clients/{clientId}/commitment)
80. **RED**: Valid rotation returns 200 with rotatedAt
81. **RED**: No Bearer token returns 401
82. **RED**: Bearer token for different client returns 403
83. **RED**: Missing currentProof / newCommitment / newCommitmentProof returns 400
84. **RED**: Malformed base64 in newCommitment returns 400
85. **RED**: Invalid currentProof returns 401, counts toward lockout
86. **RED**: Same commitment returns 409
87. **RED**: Rate limiting returns 429 with Retry-After
88. **RED**: Service at capacity returns 503 with Retry-After
89. **RED**: Revoked client returns 401, indistinguishable
90. **RED**: Extra fields in request body are ignored

### Phase 11: Timing Safety (HTTP layer)
91. **RED**: Enrollment errors are timing-indistinguishable (duplicate vs. invalid proof vs. stolen commitment)
92. **RED**: Challenge refusal errors are timing-indistinguishable (unknown vs. invalid vs. revoked vs. locked)
93. **RED**: Verification refusal errors are timing-indistinguishable (all 6 failure modes)
94. **RED**: Revocation responses are timing-indistinguishable (active vs. revoked vs. unknown)

### Phase 12: API Versioning
95. **RED**: All endpoints reachable under /v1
96. **RED**: /v2 returns 404 with version-not-available message
97. **RED**: Root path / returns 404 with versioning hint
98. **RED**: Header-based versioning returns 404 with URL-path hint

### Phase 13: Access Log Security
99. **RED**: Access logs do not contain request bodies
100. **RED**: Access logs do not contain base64 cryptographic material
101. **RED**: Access logs do not contain Authorization header values
102. **RED**: Access logs record method, path, status, timing, and X-Request-Id only

### Phase 14: Integration Smoke Tests (end-to-end)
103. **RED**: Full enrollment → challenge → verify → resource access flow via HTTP
104. **RED**: Full enrollment → revocation → challenge refusal flow via HTTP
105. **RED**: Full enrollment → verify → rotation → re-verify flow via HTTP
