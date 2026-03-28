// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollmentPolicy } from "../../../../src/client-registration/domain/service/enrollment-policy.js";
import type { CommitmentVerifier } from "../../../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type {
  ProofOfPossessionVerifier,
  ProofOfPossessionData,
} from "../../../../src/client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
import type { EnrollmentError } from "../../../../src/shared/errors.js";

function createStubCommitmentVerifier(
  overrides: Partial<CommitmentVerifier> = {},
): CommitmentVerifier {
  return {
    isCanonical: overrides.isCanonical ?? (() => true),
    isValidGroupElement: overrides.isValidGroupElement ?? (() => true),
    isIdentityElement: overrides.isIdentityElement ?? (() => false),
  };
}

function createStubProofVerifier(
  valid: boolean = true,
): ProofOfPossessionVerifier {
  return {
    verify: () => valid,
  };
}

function validProof(): ProofOfPossessionData {
  return {
    announcement: new Uint8Array(32).fill(1),
    responseS: new Uint8Array(32).fill(2),
    responseR: new Uint8Array(32).fill(3),
  };
}

function validCommitmentBytes(): Uint8Array {
  return new Uint8Array(32).fill(42);
}

describe("EnrollmentPolicy", () => {
  it("returns MISSING_COMMITMENT when commitment bytes are undefined", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(),
    );

    const result = policy.validate(undefined, validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("MISSING_COMMITMENT");
    expect(result!.message).toBe("Commitment bytes are required");
    expect(result!.name).toBe("EnrollmentError");
  });

  it("returns INVALID_ENCODING when commitment is not canonical", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toBe("Commitment encoding is not canonical");
  });

  it("returns INVALID_GROUP_ELEMENT when commitment is not a valid group element", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isValidGroupElement: () => false }),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_GROUP_ELEMENT");
    expect(result!.message).toBe("Commitment is not a valid group element");
  });

  it("returns IDENTITY_ELEMENT when commitment is the identity element", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isIdentityElement: () => true }),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("IDENTITY_ELEMENT");
    expect(result!.message).toBe("Commitment must not be the identity element");
  });

  it("returns MISSING_PROOF when proof is undefined", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), undefined, "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("MISSING_PROOF");
    expect(result!.message).toBe("Proof of possession is required");
  });

  it("returns INVALID_PROOF when proof verification fails", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(false),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_PROOF");
    expect(result!.message).toBe("Proof of possession is invalid");
  });

  it("returns null when all validations pass", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(true),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).toBeNull();
  });

  it("returns INVALID_PROOF for all-zero bytes as proof of possession", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(false),
    );

    const zeroProof: ProofOfPossessionData = {
      announcement: new Uint8Array(32),
      responseS: new Uint8Array(32),
      responseR: new Uint8Array(32),
    };

    const result = policy.validate(validCommitmentBytes(), zeroProof, "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_PROOF");
  });

  it("returns INVALID_PROOF for degenerate scalar values (zero response scalars)", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(false),
    );

    const degenerateProof: ProofOfPossessionData = {
      announcement: new Uint8Array(32).fill(1),
      responseS: new Uint8Array(32), // zero scalar
      responseR: new Uint8Array(32), // zero scalar
    };

    const result = policy.validate(validCommitmentBytes(), degenerateProof, "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_PROOF");
  });

  it("checks validation order: canonical before group element", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({
        isCanonical: () => false,
        isValidGroupElement: () => false,
      }),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_ENCODING");
  });

  it("checks validation order: group element before identity", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({
        isValidGroupElement: () => false,
        isIdentityElement: () => true,
      }),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("INVALID_GROUP_ELEMENT");
  });

  it("checks validation order: identity before proof", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier({ isIdentityElement: () => true }),
      createStubProofVerifier(false),
    );

    const result = policy.validate(validCommitmentBytes(), validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("IDENTITY_ELEMENT");
  });

  it("returns MISSING_COMMITMENT when commitment bytes are null", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(),
    );

    const result = policy.validate(null as any, validProof(), "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("MISSING_COMMITMENT");
    expect(result!.message).toBe("Commitment bytes are required");
  });

  it("returns MISSING_PROOF when proof is null", () => {
    const policy = new EnrollmentPolicy(
      createStubCommitmentVerifier(),
      createStubProofVerifier(),
    );

    const result = policy.validate(validCommitmentBytes(), null as any, "client-1");

    expect(result).not.toBeNull();
    expect(result!.code).toBe("MISSING_PROOF");
    expect(result!.message).toBe("Proof of possession is required");
  });
});
