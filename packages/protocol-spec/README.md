# @2fapi/protocol-spec

> Canonical protocol specification for 2FApi Zero-Knowledge Proof Authentication.

This package contains **no implementation** — only constants, types, and interfaces that define the 2FApi protocol. It is the shared contract between clients and servers.

## Installation

```bash
npm install @2fapi/protocol-spec
```

## What's Included

- **Protocol constants**: version, domain separation tags, byte lengths
- **TypeScript interfaces**: TranscriptFields, ProofData, ChallengeData, CommitmentData
- **Error codes**: canonical error codes for all protocol operations
- **Specification documents**: canonical Fiat-Shamir transcript format, test vectors

## Protocol Overview

2FApi uses a Schnorr/Sigma proof system over Ristretto255 with Pedersen commitments:

- **Commitment**: `C = s·G + r·H` (client stores secret, server stores commitment)
- **Proof**: Sigma protocol with Fiat-Shamir transform for non-interactivity
- **Security**: 128-bit under DLOG assumption in Random Oracle Model
- **Transcript**: Length-prefixed canonical serialization with domain separation

## Specification

See [`spec/protocol.md`](./spec/protocol.md) for the full protocol specification.

## License

Apache-2.0 — Free for any use.
