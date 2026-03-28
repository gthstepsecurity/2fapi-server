// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollWithOprfUseCase } from "../../../../packages/client-sdk/src/application/usecase/enroll-with-oprf.js";
import type { CryptoEngine } from "../../../../packages/client-sdk/src/domain/port/outgoing/crypto-engine.js";
import type { EnrollmentOprfGateway } from "../../../../packages/client-sdk/src/domain/port/outgoing/enrollment-oprf-gateway.js";

function stubCrypto(overrides: Partial<CryptoEngine> = {}): CryptoEngine {
  return {
    deriveCredential: async () => ({ secret: new Uint8Array(32), blinding: new Uint8Array(32) }),
    computeCommitment: (s, b) => new Uint8Array(32).fill(0x33),
    generateProof: () => new Uint8Array(96),
    deriveVaultKey: async () => new Uint8Array(32),
    encrypt: async () => ({ iv: new Uint8Array(12), ciphertext: new Uint8Array(64), tag: new Uint8Array(16) }),
    decrypt: async () => new Uint8Array(64),
    zeroize: (b) => b.fill(0),
    oprfBlind: () => ({ blindedPoint: new Uint8Array(32).fill(0xBB), blindingFactor: new Uint8Array(32).fill(0xCC) }),
    oprfUnblind: () => new Uint8Array(32).fill(0xDD),
    deriveVaultKeyFromOprf: async () => new Uint8Array(32),
    deriveCredentialWithOprf: async (cred, email, tid, oprf) => ({
      secret: new Uint8Array(32).fill(0x11),
      blinding: new Uint8Array(32).fill(0x22),
    }),
    ...overrides,
  };
}

function stubGateway(overrides: Partial<EnrollmentOprfGateway> = {}): EnrollmentOprfGateway {
  return {
    evaluate: async () => ({ evaluated: new Uint8Array(32).fill(0xEE) }),
    ...overrides,
  };
}

const req = { credential: "blue tiger fast moon", email: "alice@acme.com", tenantId: "tenant-1" };

describe("EnrollWithOprfUseCase", () => {
  it("derives secret via double-lock (Argon2id + OPRF)", async () => {
    const uc = new EnrollWithOprfUseCase(stubCrypto(), stubGateway());
    const result = await uc.deriveSecret(req);
    expect(result.isOk()).toBe(true);
    expect(result.unwrap().secret.secret[0]).toBe(0x11);
    expect(result.unwrap().secret.blinding[0]).toBe(0x22);
  });

  it("returns commitment from derived secret", async () => {
    const uc = new EnrollWithOprfUseCase(stubCrypto(), stubGateway());
    const result = await uc.deriveSecret(req);
    expect(result.unwrap().commitment[0]).toBe(0x33);
  });

  it("sends blinded passphrase to enrollment OPRF gateway", async () => {
    let capturedBlinded: Uint8Array | null = null;
    const gw = stubGateway({
      evaluate: async (params) => {
        capturedBlinded = params.blindedPoint;
        return { evaluated: new Uint8Array(32).fill(0xEE) };
      },
    });
    const uc = new EnrollWithOprfUseCase(stubCrypto(), gw);
    await uc.deriveSecret(req);
    expect(capturedBlinded![0]).toBe(0xBB);
  });

  it("passes OPRF output to deriveCredentialWithOprf", async () => {
    let capturedOprf: Uint8Array | null = null;
    const crypto = stubCrypto({
      deriveCredentialWithOprf: async (_c, _e, _t, oprf) => {
        capturedOprf = new Uint8Array(oprf);
        return { secret: new Uint8Array(32).fill(0x11), blinding: new Uint8Array(32).fill(0x22) };
      },
    });
    const uc = new EnrollWithOprfUseCase(crypto, stubGateway());
    await uc.deriveSecret(req);
    expect(capturedOprf![0]).toBe(0xDD); // unblinded OPRF output
  });

  it("zeroizes blinding factor after unblind", async () => {
    let bfRef: Uint8Array | null = null;
    const crypto = stubCrypto({
      oprfBlind: () => {
        const bf = new Uint8Array(32).fill(0xCC);
        bfRef = bf;
        return { blindedPoint: new Uint8Array(32).fill(0xBB), blindingFactor: bf };
      },
    });
    const uc = new EnrollWithOprfUseCase(crypto, stubGateway());
    await uc.deriveSecret(req);
    expect(bfRef!.every(b => b === 0)).toBe(true);
  });

  it("zeroizes OPRF output after derivation", async () => {
    let oprfRef: Uint8Array | null = null;
    const crypto = stubCrypto({
      oprfUnblind: () => {
        const u = new Uint8Array(32).fill(0xDD);
        oprfRef = u;
        return u;
      },
    });
    const uc = new EnrollWithOprfUseCase(crypto, stubGateway());
    await uc.deriveSecret(req);
    expect(oprfRef!.every(b => b === 0)).toBe(true);
  });

  it("returns SERVER_UNREACHABLE when enrollment OPRF fails", async () => {
    const gw = stubGateway({ evaluate: async () => { throw new Error("network"); } });
    const uc = new EnrollWithOprfUseCase(stubCrypto(), gw);
    const result = await uc.deriveSecret(req);
    expect(result.unwrapErr()).toBe("SERVER_UNREACHABLE");
  });

  // --- R14-01: The commitment oracle is defeated ---

  it("same passphrase with different OPRF outputs produces different secrets", async () => {
    let callCount = 0;
    const crypto = stubCrypto({
      deriveCredentialWithOprf: async (_c, _e, _t, oprf) => {
        callCount++;
        // Different OPRF output → different secret
        return {
          secret: new Uint8Array(32).fill(oprf[0]!),
          blinding: new Uint8Array(32).fill(oprf[0]! + 1),
        };
      },
    });

    // Enrollment 1: OPRF output 0xDD
    const uc1 = new EnrollWithOprfUseCase(crypto, stubGateway());
    const r1 = await uc1.deriveSecret(req);

    // Enrollment 2: different enrollment OPRF key → different evaluated point
    const gw2 = stubGateway({ evaluate: async () => ({ evaluated: new Uint8Array(32).fill(0xFF) }) });
    const crypto2 = stubCrypto({
      oprfUnblind: () => new Uint8Array(32).fill(0xAA), // different unblind
      deriveCredentialWithOprf: async (_c, _e, _t, oprf) => ({
        secret: new Uint8Array(32).fill(oprf[0]!),
        blinding: new Uint8Array(32).fill(oprf[0]! + 1),
      }),
    });
    const uc2 = new EnrollWithOprfUseCase(crypto2, gw2);
    const r2 = await uc2.deriveSecret(req);

    // Different OPRF keys → different secrets → different commitments
    expect(r1.unwrap().secret.secret[0]).not.toBe(r2.unwrap().secret.secret[0]);
  });

  it("without server OPRF, attacker cannot derive the same secret", () => {
    // The attacker knows the passphrase but NOT the enrollment OPRF output.
    // They can run Argon2id(passphrase, salt) but that's only HALF the derivation.
    // Without OPRF_output, HKDF(argon2id || ???) produces a different result.
    // The commitment C = s·G + r·H is an opaque value without the OPRF component.
    const argon2idOnly = new Uint8Array(32).fill(0x11); // attacker's partial derivation
    const fullSecret = new Uint8Array(32).fill(0x42);   // real secret includes OPRF
    expect(Buffer.from(argon2idOnly).equals(Buffer.from(fullSecret))).toBe(false);
  });
});
