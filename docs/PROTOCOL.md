# 2FApi — Canonical Fiat-Shamir Transcript Specification

## Overview

This document defines the canonical transcript format for the 2FApi Sigma protocol
(Schnorr-like proof of knowledge of a Pedersen commitment opening over Ristretto255).

The transcript is the input to the Fiat-Shamir hash function that produces the challenge
scalar `c`. Both client and server MUST produce identical transcripts for verification to succeed.

## Authoritative Implementation

**TypeScript (server-side) is the source of truth.** The canonical transcript is produced by:

- `src/zk-verification/domain/model/transcript.ts` — `Transcript.build()`
- Hashed via `@2fapi/crypto-native` NAPI binding (`hashTranscript`)

The Rust `compute_challenge()` in `crypto-core/src/sigma.rs` uses a DIFFERENT format
(no length-prefixing, different field ordering) and is NOT the production-authoritative path.
It is used only for internal Rust tests. **Do NOT use Rust `prove()` directly in production**
— use the NAPI `hash_transcript` path that accepts the TypeScript-serialized transcript.

## Canonical Transcript Format

All fields are serialized as length-prefixed blobs with **4-byte big-endian uint32** length prefixes.

### Field Order

```
tag || g || h || C || A || clientId || nonce || channelBinding
```

### Encoding

```
[4 bytes: len(tag)]   [tag bytes]
[4 bytes: len(g)]     [g bytes]          (32 bytes, compressed Ristretto255)
[4 bytes: len(h)]     [h bytes]          (32 bytes, compressed Ristretto255)
[4 bytes: len(C)]     [C bytes]          (32 bytes, compressed Ristretto255)
[4 bytes: len(A)]     [A bytes]          (32 bytes, compressed Ristretto255)
[4 bytes: len(cid)]   [clientId bytes]   (UTF-8 encoded)
[4 bytes: len(nonce)] [nonce bytes]      (24 bytes)
[4 bytes: len(cb)]    [cb bytes]         (channel binding, variable)
```

### Total Size

For standard parameters:
- tag: 16 bytes ("2FApi-v1.0-Sigma")
- g, h, C, A: 32 bytes each
- clientId: variable (UTF-8)
- nonce: 24 bytes
- channelBinding: variable

Total = 8 * 4 (length prefixes) + 16 + 32 + 32 + 32 + 32 + len(clientId) + 24 + len(channelBinding)
     = 32 + 168 + len(clientId) + len(channelBinding)
     = 200 + len(clientId) + len(channelBinding)

### Hash Function

The transcript bytes are hashed using SHA-512, then reduced to a canonical Ristretto255 scalar
via `Scalar::from_bytes_mod_order_wide()` (512-bit to 256-bit reduction modulo the group order l).

## Domain Separation Tag

The protocol tag is `"2FApi-v1.0-Sigma"` (16 bytes, ASCII).

This tag MUST appear as the first field in the transcript to prevent cross-protocol attacks.
The verifier MUST reject any proof whose domain separation tag does not match the expected value.

## Security Properties

- **Length-prefixing** prevents ambiguous concatenation attacks (e.g., `("ab", "c")` vs `("a", "bc")`)
- **Domain separation** prevents cross-protocol transcript reuse
- **Nonce binding** ensures freshness (replay resistance)
- **Channel binding** ties the proof to a specific TLS session or HTTP request context
- **Client identifier binding** prevents proof theft between clients

## WARNING: Rust vs TypeScript Transcript Incompatibility

The Rust `compute_challenge()` function in `crypto-core/src/sigma.rs`:
1. Prepends `G || H || C || A` as raw bytes (NO length-prefixing)
2. Appends `transcript_data` as raw bytes

This is fundamentally different from the TypeScript format which:
1. Length-prefixes ALL fields including G, H, C, A
2. Includes tag, clientId, nonce, and channelBinding as separate length-prefixed fields

A client using Rust `prove()` directly would produce an incompatible challenge scalar.
The NAPI `hash_transcript` binding accepts the TypeScript-serialized transcript bytes,
ensuring compatibility.

## TLS Requirements (I-10)

Production deployments MUST enforce TLS for all network communication:

- **Client to API Gateway**: TLS 1.2+ with valid certificates. Certificate validation MUST NOT be disabled.
- **API Gateway to PostgreSQL**: SSL mode `verify-full`. The server certificate chain must be validated.
- **API Gateway to Redis**: TLS-encrypted connection with certificate verification enabled.
- **Inter-service communication**: All internal service-to-service calls must use mutual TLS (mTLS) where applicable.

Self-signed certificates are acceptable for development only. Production environments MUST use certificates issued by a trusted CA.

## Data Protection (T-10)

Audit logs contain PII fields:
- `clientIdentifier`: plaintext client ID
- `sourceAddress`: client IP address

These fields are marked with `@pii` JSDoc tags in the domain model (`AuditEntry`).
Access to audit log storage MUST be restricted to authorized administrators only.
When exporting audit data to external systems, consider hashing identifiers before export.

## Post-Quantum Migration Strategy (DC10)

The current protocol relies on the Discrete Logarithm assumption over Ristretto255,
which is vulnerable to Shor's algorithm on a sufficiently large quantum computer.
Under current projections (2035+ for cryptographically relevant quantum computers),
the protocol is considered secure for the foreseeable future.

### Migration Plan

1. **Monitoring** (now): Track NIST PQC standardization progress (ML-KEM, ML-DSA, SLH-DSA).
2. **Algorithm agility** (next): Abstract the commitment scheme and proof protocol behind
   a `CryptoSuite` interface, enabling runtime selection between classical and PQ schemes.
3. **Hybrid mode** (when PQ standards mature): Run Pedersen + lattice-based commitment in
   parallel. Both proofs must verify for the transition period.
4. **Full migration** (when quantum threat is imminent): Deprecate classical-only mode,
   require PQ or hybrid proofs exclusively.

### Design Considerations

- The Pedersen commitment `C = g^s * h^r` would be replaced by a lattice-based equivalent.
- The Sigma protocol (Schnorr-like) would be replaced by a PQ zero-knowledge proof system
  (e.g., lattice-based Sigma protocols or hash-based signatures).
- Channel binding and transcript hashing are already hash-based and PQ-resistant.
- Recovery phrase hashing (Argon2id) is symmetric and PQ-resistant (Grover halves
  effective security: 128-bit → 64-bit, mitigated by increasing Argon2 parameters).
