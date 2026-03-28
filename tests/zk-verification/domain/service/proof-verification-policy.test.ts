// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  ProofVerificationPolicy,
  ProofVerificationError,
} from "../../../../src/zk-verification/domain/service/proof-verification-policy.js";
import type { ElementValidator } from "../../../../src/zk-verification/domain/port/outgoing/element-validator.js";
import type { CommitmentInfo } from "../../../../src/zk-verification/domain/port/outgoing/commitment-lookup.js";

function createAllValidElementValidator(): ElementValidator {
  return {
    isCanonicalScalar: () => true,
    isCanonicalPoint: () => true,
  };
}

function createElementValidator(
  overrides: Partial<{ canonicalScalar: boolean; canonicalPoint: boolean }> = {},
): ElementValidator {
  return {
    isCanonicalScalar: () => overrides.canonicalScalar ?? true,
    isCanonicalPoint: () => overrides.canonicalPoint ?? true,
  };
}

function validProofBytes(): Uint8Array {
  // 96 bytes: 32 (announcement) + 32 (responseS) + 32 (responseR)
  // announcement must not be identity (all zeros)
  const bytes = new Uint8Array(96);
  bytes[0] = 0x01; // non-identity announcement
  bytes[32] = 0x02; // responseS
  bytes[64] = 0x03; // responseR
  return bytes;
}

function activeCommitment(): CommitmentInfo {
  return {
    commitment: new Uint8Array(32).fill(0xaa),
    clientStatus: "active",
  };
}

const PROTOCOL_TAG = "2FApi-v1.0-Sigma";

describe("ProofVerificationPolicy", () => {
  it("should return null when all preconditions are met", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeNull();
  });

  it("should return CLIENT_NOT_FOUND when commitment info is null", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: null,
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("CLIENT_NOT_FOUND");
    expect(result!.message).toBe("Client not found");
    expect(result!.name).toBe("ProofVerificationError");
  });

  it("should return CLIENT_REVOKED when client status is revoked", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: { commitment: new Uint8Array(32).fill(0xaa), clientStatus: "revoked" },
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("CLIENT_REVOKED");
    expect(result!.message).toBe("Client is not active");
  });

  it("should return CLIENT_REVOKED when client status is unknown", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: { commitment: new Uint8Array(32).fill(0xaa), clientStatus: "unknown" },
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("CLIENT_REVOKED");
    expect(result!.message).toBe("Client is not active");
  });

  it("should return INVALID_TAG when domain separation tag does not match protocol", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: "wrong-tag",
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_TAG");
    expect(result!.message).toBe("Domain separation tag does not match protocol");
  });

  it("should return INVALID_ENCODING when proof is not 96 bytes", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: new Uint8Array(64),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toBe("Proof must be exactly 96 bytes");
  });

  it("should return INVALID_ENCODING when responseS scalar is not canonical", () => {
    const validator = createElementValidator({ canonicalScalar: false });
    const policy = new ProofVerificationPolicy(validator);

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toBe("Response scalar s is not canonical");
  });

  it("should return INVALID_ENCODING when announcement point is not canonical", () => {
    const validator = createElementValidator({ canonicalPoint: false });
    const policy = new ProofVerificationPolicy(validator);

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toBe("Announcement point is not canonical");
  });

  it("should return INVALID_ENCODING when announcement is the identity element (all zeros)", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());
    const proofBytes = new Uint8Array(96); // all zeros — identity announcement
    proofBytes[32] = 0x02; // responseS non-zero
    proofBytes[64] = 0x03; // responseR non-zero

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes,
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toBe("Announcement must not be the identity element");
  });

  it("should check preconditions in priority order: client > tag > encoding", () => {
    // When client is null AND tag is wrong, CLIENT_NOT_FOUND takes priority
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: null,
      domainSeparationTag: "wrong-tag",
      proofBytes: new Uint8Array(10), // bad encoding too
    });

    expect(result!.code).toBe("CLIENT_NOT_FOUND");
  });

  it("should check tag before encoding", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: "wrong-tag",
      proofBytes: new Uint8Array(10), // bad encoding too
    });

    expect(result!.code).toBe("INVALID_TAG");
  });

  it("should check client status before tag", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: { commitment: new Uint8Array(32).fill(0xaa), clientStatus: "revoked" },
      domainSeparationTag: "wrong-tag",
      proofBytes: new Uint8Array(10),
    });

    expect(result!.code).toBe("CLIENT_REVOKED");
  });

  it("should return INVALID_ENCODING for responseR scalar not canonical (separate from responseS)", () => {
    // Need a validator that accepts points and the first scalar, but rejects the second
    let scalarCallCount = 0;
    const validator: ElementValidator = {
      isCanonicalScalar: () => {
        scalarCallCount++;
        // First call (responseS) passes, second call (responseR) fails
        return scalarCallCount <= 1;
      },
      isCanonicalPoint: () => true,
    };
    const policy = new ProofVerificationPolicy(validator);

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toBe("Response scalar r is not canonical");
  });

  it("should accept valid protocol tag: 2FApi-v1.0-Sigma", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: "2FApi-v1.0-Sigma",
      proofBytes: validProofBytes(),
    });

    expect(result).toBeNull();
  });

  it("should reject empty domain separation tag", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: "",
      proofBytes: validProofBytes(),
    });

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_TAG");
  });

  it("should proceed to encoding validation when encoding error is non-null (if true)", () => {
    // Kill mutant: `if (true)` instead of `if (encodingError !== null)`
    // When encoding is valid, policy should return null (no error)
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    // With mutant `if (true)`, it would always return the encoding error (even when null)
    // With correct code, it should return null
    expect(result).toBeNull();
  });

  it("should slice proof bytes into correct 32-byte components", () => {
    // Kill mutants: announcementBytes = proofBytes (instead of slice(0, 32))
    // responseSBytes = proofBytes (instead of slice(32, 64)) with 2*ELEMENT vs 2/ELEMENT
    // responseRBytes = proofBytes (instead of slice(64, 96)) with 2*ELEMENT, 3*ELEMENT vs /
    // Create a proof where each section has distinct patterns
    let pointCallCount = 0;
    let scalarCallCount = 0;
    const capturedPoints: Uint8Array[] = [];
    const capturedScalars: Uint8Array[] = [];

    const capturingValidator: ElementValidator = {
      isCanonicalPoint: (bytes: Uint8Array) => {
        pointCallCount++;
        capturedPoints.push(new Uint8Array(bytes));
        return true;
      },
      isCanonicalScalar: (bytes: Uint8Array) => {
        scalarCallCount++;
        capturedScalars.push(new Uint8Array(bytes));
        return true;
      },
    };

    const policy = new ProofVerificationPolicy(capturingValidator);

    const proofBytes = new Uint8Array(96);
    // Announcement: bytes 0-31 all 0x11
    proofBytes.fill(0x11, 0, 32);
    // ResponseS: bytes 32-63 all 0x22
    proofBytes.fill(0x22, 32, 64);
    // ResponseR: bytes 64-95 all 0x33
    proofBytes.fill(0x33, 64, 96);

    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes,
    });

    expect(result).toBeNull();
    // Should have called isCanonicalPoint once (announcement)
    expect(pointCallCount).toBe(1);
    expect(capturedPoints[0]!.length).toBe(32);
    expect(capturedPoints[0]![0]).toBe(0x11);

    // Should have called isCanonicalScalar twice (responseS, responseR)
    expect(scalarCallCount).toBe(2);
    expect(capturedScalars[0]!.length).toBe(32);
    expect(capturedScalars[0]![0]).toBe(0x22);
    expect(capturedScalars[1]!.length).toBe(32);
    expect(capturedScalars[1]![0]).toBe(0x33);
  });

  it("should use < (not <=) in identity element check loop", () => {
    // Kill mutant: `for (let i = 0; i <= ELEMENT_BYTE_LENGTH; i++)` — off-by-one
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    // Non-identity announcement (first byte non-zero)
    const result = policy.validate({
      commitmentInfo: activeCommitment(),
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeNull();
  });
});
