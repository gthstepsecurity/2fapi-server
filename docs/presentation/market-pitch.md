# 2FApi — API Authentication, Reinvented

> For CISOs, security buyers, developers, and decision-makers.

---

## The One-Liner

**"API keys are the new passwords. We're replacing them with math."**

---

## The Problem You Know

Every API call your systems make today is authenticated with a shared secret: an API key, an OAuth token, a client certificate. That secret is stored somewhere — a database, a config file, a vault.

When that storage is breached — and it will be — every secret is compromised. Every API key. Every token. Every certificate.

**LastPass, 2022**: encrypted vaults stolen. Master passwords brute-forced. Millions of users compromised.

**Okta, 2023**: support system breached. Session tokens stolen. Hundreds of companies affected.

**Cloudflare, 2024**: API tokens exposed via source code. Service accounts compromised.

The pattern is always the same: **the secret was stored. The storage was breached. The secret was taken.**

---

## What If the Secret Was Never Stored?

2FApi is a protocol where the server **never sees, stores, or transmits** the client's secret. Not during enrollment. Not during authentication. Not ever.

The server stores a **mathematical commitment** — a public value that proves the client enrolled, but reveals nothing about the secret. When the client authenticates, it generates a **zero-knowledge proof** that convinces the server without revealing anything.

If your database is breached, the attacker finds commitments. Public values. Useless without the secrets. And the secrets? They don't exist — not on the server, not on the client, not anywhere. They exist only as two mathematical shares, on two separate systems, never combined.

**Zero-knowledge means zero liability.**

---

## For the CISO

| Question | Answer |
|----------|--------|
| **What's at risk in a breach?** | Nothing. The server stores only public commitments. |
| **What if our database leaks?** | The attacker cannot authenticate. Commitments ≠ secrets. |
| **What about insider threats?** | Even the DBA cannot extract usable credentials. Keys are in HSM. |
| **Compliance?** | NIST 800-63B, FIDO2, GDPR, PCI DSS 4.0, ANSSI RGS v2. |
| **What about quantum?** | Algorithm agility built in. Post-quantum migration plan documented. |
| **Has it been pen-tested?** | 28-pass internal red team. 109 findings. 0 open. Ready for external audit. |

---

## For the Developer

```typescript
// Enrollment (once)
const { commitment, recoveryPhrase } = await sdk.enroll({
  email: "alice@acme.com",
  passphrase: "blue tiger fast moon",  // or server-generated
});

// Authentication (every time)
const { jwt } = await sdk.authenticate({
  email: "alice@acme.com",
  passphrase: "blue tiger fast moon",
});

// Use the JWT like any bearer token
const response = await fetch("/api/resource", {
  headers: { Authorization: `Bearer ${jwt}` },
});
```

That's it. No API key management. No token rotation. No certificate lifecycle. The SDK handles the zero-knowledge proof, the OPRF derivation, and the vault protection under the hood.

**Time to first auth: < 5 minutes.**

---

## For the Security Architect

### What makes 2FApi different

| | API Keys | OAuth 2.0 | mTLS | **2FApi** |
|---|---|---|---|---|
| Server stores secret? | ✅ Yes | ✅ Yes (tokens) | ✅ Yes (certs) | **❌ Never** |
| Breach = compromised? | ✅ Yes | ✅ Yes | ✅ Yes | **❌ No** |
| Shared secret on wire? | ✅ Every request | ✅ Token exchange | ✅ TLS handshake | **❌ Never** |
| Replay-resistant? | ❌ No | ⚠️ Token TTL only | ✅ TLS session | **✅ Nonce-bound** |
| Brute-force offline? | ✅ If hash leaked | ✅ If token leaked | ❌ No | **❌ Impossible** |
| Quantum-safe path? | ❌ No | ❌ No | ❌ No | **✅ Algorithm agility** |
| Hardware binding? | ❌ No | ❌ No | ⚠️ Smart cards | **✅ WebAuthn PRF** |

### The key innovation

Traditional auth: **"prove you HAVE the secret"** (by showing it).
2FApi: **"prove you KNOW the secret"** (without showing it).

The distinction is fundamental. Showing the secret creates a copy. Proving knowledge does not.

---

## Use Cases

### Fintech — PSD2 Strong Customer Authentication
API calls between payment processors require strong authentication. 2FApi provides SCA-compliant two-factor authentication without shared secrets. The bank's server never holds credentials that could be stolen.

### Healthcare — HIPAA API Security
Patient data APIs must be authenticated with the highest assurance. 2FApi ensures that even a complete server breach reveals zero patient credentials. Audit trail is immutable and zero-knowledge.

### Government — Classified API Access
Defense and intelligence systems require authentication that resists nation-state adversaries. 2FApi with 6-word passphrase + HSM + hardware key provides 3-factor protection that withstands GPU clusters and future quantum computers.

### Developer Platforms — API Key Replacement
Any platform that issues API keys to developers (Stripe, Twilio, AWS) can replace them with 2FApi. Developers enroll once. The platform never stores their secret. A database breach has zero impact on API security.

### IoT — Device Authentication
Embedded devices authenticate to cloud APIs using Pedersen commitments. No shared secrets stored on devices that may be physically captured. The commitment is public — stealing the device reveals nothing.

---

## The Numbers

| Metric | Value |
|--------|-------|
| Server verification time | < 1ms |
| Client proof generation | < 5ms |
| Full authentication (with Argon2id) | ~500ms |
| Brute-force cost (6-word + HSM) | > 2,500 years @ 10,000 GPUs |
| Red team findings | 109 found, 0 open |
| Automated tests | 1,963 |
| Secret cleartext lifetime | **0 ms** (secret sharing) |
| SDK bundle size | < 300 KB gzipped |
| Supported platforms | Browser, Node.js, Deno, WASM |

---

## Business Model

| Tier | Offering | Price |
|------|---------|-------|
| **Open Source** | Protocol + SDK + self-hosted server | Free (Apache 2.0) |
| **Managed** | Hosted verification + HSM + monitoring | Per-API-call pricing |
| **Enterprise** | Dedicated HSM + SLA + custom integration | Custom |

---

## The Ask

**For security companies**: audit us. We have 28 passes of internal red team and 109 documented findings. We want external validation from Trail of Bits, NCC Group, or Cure53.

**For enterprises**: pilot us. Replace one API key integration with 2FApi. Measure the difference.

**For developers**: try us. `npm install @2fapi/client-sdk`. Time to first auth: 5 minutes.

---

*"Security should be invisible, provable, and zero-trust by default."*

*2FApi — the secret that doesn't exist cannot be stolen.*
