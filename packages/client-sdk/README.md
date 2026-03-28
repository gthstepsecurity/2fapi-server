# @2fapi/client-sdk

> Generate Zero-Knowledge Proofs for API authentication. Prove you know the secret. Never reveal it.

## Installation

```bash
npm install @2fapi/client-sdk
```

## Quick Start

```typescript
import { setCryptoModule, generateCommitment, generateProof } from "@2fapi/client-sdk";
import * as crypto from "@2fapi/crypto-native"; // or @2fapi/crypto-wasm for browser

// 1. Load the crypto backend (once at startup)
setCryptoModule(crypto);

// 2. Generate a commitment (during registration)
const secret = crypto.randomScalar();
const blindingFactor = crypto.randomScalar();
const commitment = generateCommitment(secret, blindingFactor);

// 3. Register with the server
await fetch("https://auth.example.com/v1/clients", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    clientIdentifier: "my-service",
    commitment: Buffer.from(commitment).toString("base64"),
    proofOfPossession: Buffer.from(proofOfPossession).toString("base64"),
  }),
});

// 4. Authenticate (each session)
const challenge = await requestChallenge("my-service");

const proof = generateProof({
  secret,
  blindingFactor,
  commitment,
  nonce: challenge.nonce,
  channelBinding: tlsExporterValue,
  clientIdentifier: "my-service",
});

const token = await verifyAndGetToken("my-service", challenge.id, proof);
// Use token.accessToken for API calls
```

## How It Works

1. **Registration** (once): Client generates secret + blinding factor, computes Pedersen commitment `C = s·G + r·H`, sends C to server
2. **Challenge** (each auth): Client requests a fresh nonce from the server
3. **Proof** (each auth): Client generates a Sigma proof bound to the nonce
4. **Verification**: Server verifies the proof against the stored commitment — without ever learning the secret

The server **never stores any secret**. A database breach reveals only commitments — mathematically useless without the client's secret.

## License

Apache-2.0 — Free for any use.
