# 2FApi — Technical Overview

> For security architects, cryptographers, and engineering leads.

---

## What 2FApi Is

2FApi is a zero-knowledge proof authentication protocol for APIs. The client proves it knows a secret without revealing the secret. The server verifies the proof without learning the secret. No shared secrets are stored anywhere.

**One sentence**: "Replace API keys with math."

---

## The Problem

| Current method | What the server stores | If breached |
|---------------|----------------------|-------------|
| API keys | The key itself (plaintext or hashed) | Attacker has the key |
| OAuth tokens | Token + refresh token | Attacker has session access |
| mTLS certificates | Certificate + trusted CA chain | Attacker forges certificates |
| **2FApi** | **A commitment (public value)** | **Attacker has nothing usable** |

The commitment is a mathematical lock. Without the key (the secret), it cannot be opened. And the key is never sent to the server — not during enrollment, not during authentication, not ever.

---

## How It Works

### Three primitives

1. **Pedersen Commitment** (enrollment)
   ```
   C = s·G + r·H
   ```
   The client derives secret `s` and blinding `r` from a passphrase. It computes commitment `C` and sends `C` to the server. The server stores `C`. The secret `s` is never transmitted.

2. **Sigma Proof** (authentication)
   ```
   Prover: A = k_s·G + k_r·H         (random announcement)
   Challenge: c = H(G, H, C, A, nonce)  (Fiat-Shamir)
   Response: z_s = k_s + c·s, z_r = k_r + c·r
   Verifier: z_s·G + z_r·H == A + c·C   (check)
   ```
   The client proves knowledge of `(s, r)` opening `C` without revealing them. The proof is non-interactive (one round-trip) and bound to a fresh nonce (no replay).

3. **OPRF** (key derivation)
   ```
   Client: B = r · H(password)          (blind)
   Server: E = k · B                     (evaluate)
   Client: U = r⁻¹ · E = k · H(password) (unblind)
   ```
   The server helps derive a key without seeing the password. The client gets OPRF(k, password) without seeing `k`. Neither party learns the other's secret.

### The protocol flow

```
ENROLLMENT (once):
  1. Client: passphrase → Argon2id → OPRF → (s₁, r₁) client share
  2. Server: OPRF → (s₂, r₂) server share
  3. Both: C = C₁ + C₂ (commitment, public)
  4. Secret s = s₁ + s₂ is NEVER computed

AUTHENTICATION (every login):
  1. Server: issues challenge nonce n
  2. Client: computes partial proof with s₁
  3. Server: computes partial proof with s₂, combines, verifies
  4. Server: issues JWT on success
  5. Secret s is NEVER reconstructed
```

---

## Security Properties

| Property | Guarantee | How |
|----------|-----------|-----|
| **Zero-knowledge** | Server learns nothing about the secret | Sigma protocol + OPRF blinding |
| **No shared secrets** | Server stores only the commitment (public) | Pedersen commitment binding |
| **Replay-resistant** | Each proof is unique and one-time | Fresh nonce + Fiat-Shamir binding |
| **Offline brute-force immune** | Cannot crack without server cooperation | Double-lock OPRF (Argon2id + server OPRF) |
| **Forward secrecy** | Past sessions uncompromised by future breach | Vault TTL + key rotation |
| **Hardware binding** | Optional 3rd factor via TPM/Secure Enclave | WebAuthn PRF extension |
| **Secret never exists** | The full secret is never in cleartext anywhere | 2-of-2 additive secret sharing |

---

## Cryptographic Stack

| Layer | Primitive | Standard |
|-------|-----------|----------|
| Curve | Ristretto255 (Curve25519 with cofactor elimination) | draft-irtf-cfrg-ristretto255 |
| Commitment | Pedersen (perfectly hiding, computationally binding) | Pedersen 1991 |
| Proof | Schnorr/Sigma with Fiat-Shamir transform | Schnorr 1989, Fiat-Shamir 1986 |
| KDF | Argon2id (memory-hard, data-independent first pass) | RFC 9106, OWASP recommended |
| OPRF | Oblivious PRF over Ristretto255 | RFC 9497 |
| Encryption | AES-256-GCM (hardware-accelerated via AES-NI) | NIST SP 800-38D |
| Key derivation | HKDF-SHA512 | RFC 5869 |
| Nonces | RFC 6979 hybrid (deterministic + OS random) | RFC 6979 |
| Hashing | SHA-512 with domain separation | FIPS 180-4 |

All cryptographic operations on secret data are constant-time (`subtle` crate). All secret memory is zeroized after use (`zeroize` crate with `ZeroizeOnDrop`).

---

## Architecture

### Storage tiers (client-side vault)

| Tier | Factors | Protection |
|------|---------|-----------|
| **Tier 0** | Passphrase only | Argon2id + OPRF (nothing persisted) |
| **Tier 1a** | Password + OPRF | AES-256-GCM vault in localStorage |
| **Tier 1b** | Password + OPRF + hardware | Vault + WebAuthn PRF (TPM-bound) |
| **Tier 2** | Biometric | WebAuthn Credential Manager |

### Key hierarchy

```
enrollment_oprf_key (per user, HSM)    → credential derivation
vault_oprf_key (per device, HSM)       → vault encryption
hardware_key (per device, TPM)          → device binding
```

### Zero-trust boundaries

The system trusts NOTHING:
- Not the browser (secrets in WASM, dummy operations mask real ones)
- Not the network (OPRF blinds all values, channel binding)
- Not the server (secret sharing, server sees only shares)
- Not the database (HSM for keys, encrypted at rest)
- Not the OS (RFC 6979 nonces, timing detection)
- Not the hardware vendor (dual-HSM key splitting)

---

## Performance

| Operation | Time | Where |
|-----------|------|-------|
| Argon2id derivation | ~500ms | Client WASM (memory-hard, intentional) |
| OPRF blind/unblind | <2ms | Client WASM |
| OPRF evaluation | <1ms | Server (scalar multiplication) |
| Sigma proof generation | <1ms | Client WASM |
| Sigma proof verification | <1ms | Server |
| AES-256-GCM vault decrypt | <1ms | Client WebCrypto (AES-NI) |
| **Total authentication** | **~500ms** | Dominated by Argon2id (anti-brute-force) |

---

## Red Team Validation

- **28 passes** of internal offensive security audit
- **109 findings** identified, categorized, and addressed
- **39 code fixes** implemented with tests
- **1963 automated tests** (zero failures)
- **0 open showstoppers**
- Attack vectors tested: cryptanalysis, implementation, network, physical, business logic, operations, trust boundaries, traffic analysis, power analysis, debugger, process forensics
- The secret has **zero cleartext lifetime** (2-of-2 secret sharing)
- The system achieves **perfect indistinguishability** across 12 observable metrics

---

## What 2FApi Is NOT

- **Not a password manager**: it replaces passwords with zero-knowledge proofs
- **Not an identity provider**: it's an authentication PROTOCOL, not a service
- **Not OAuth/OIDC**: no tokens are shared, no bearer credentials
- **Not mTLS**: no certificates to manage, no CA trust chain
- **Not blockchain**: no ledger, no consensus, no gas fees

---

## Deployment

Open-source protocol + commercial managed service.
- **Self-hosted**: Apache 2.0, deploy with your own HSM
- **Managed SaaS**: we handle the HSM, monitoring, and key rotation
- **SDK**: TypeScript (browser + Node.js + Deno), Rust core

Compliance: NIST SP 800-63B, FIDO2, GDPR Art. 32, PCI DSS 4.0, ANSSI RGS v2.
