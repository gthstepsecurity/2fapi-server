// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RotationPolicy } from "../../../../src/client-registration/domain/service/rotation-policy.js";
import { Commitment } from "../../../../src/client-registration/domain/model/commitment.js";
import type { CommitmentVerifier } from "../../../../src/client-registration/domain/port/outgoing/commitment-verifier.js";
import type { RotationProofVerifier } from "../../../../src/client-registration/domain/port/outgoing/rotation-proof-verifier.js";

function createStubCommitmentVerifier(
  overrides: Partial<CommitmentVerifier> = {},
): CommitmentVerifier {
  return {
    isCanonical: overrides.isCanonical ?? (() => true),
    isValidGroupElement: overrides.isValidGroupElement ?? (() => true),
    isIdentityElement: overrides.isIdentityElement ?? (() => false),
  };
}

function createStubRotationProofVerifier(valid: boolean = true): RotationProofVerifier {
  return {
    verify: () => valid,
  };
}

function currentCommitment(): Commitment {
  return Commitment.fromBytes(new Uint8Array(32).fill(0xab));
}

function newCommitmentBytes(byte: number = 0xcd): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

describe("RotationPolicy", () => {
  it("returns null for valid rotation parameters", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(true),
    );

    const error = policy.validate(
      currentCommitment(),
      new Uint8Array(32).fill(1),
      newCommitmentBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error).toBeNull();
  });

  it("returns error when new commitment equals current commitment", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(true),
    );

    const current = currentCommitment();
    const error = policy.validate(
      current,
      new Uint8Array(32).fill(1),
      current.toBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error).not.toBeNull();
    expect(error!.code).toBe("SAME_COMMITMENT");
    expect(error!.message).toBe("New commitment must differ from the current commitment");
  });

  it("returns error when new commitment is the identity element", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier({ isIdentityElement: () => true }),
      createStubRotationProofVerifier(true),
    );

    const error = policy.validate(
      currentCommitment(),
      new Uint8Array(32).fill(1),
      newCommitmentBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error).not.toBeNull();
    expect(error!.code).toBe("IDENTITY_ELEMENT");
    expect(error!.message).toBe("New commitment must not be the identity element");
  });

  it("returns error when new commitment encoding is not canonical", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubRotationProofVerifier(true),
    );

    const error = policy.validate(
      currentCommitment(),
      new Uint8Array(32).fill(1),
      newCommitmentBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error).not.toBeNull();
    expect(error!.code).toBe("INVALID_ENCODING");
    expect(error!.message).toBe("New commitment encoding is not canonical");
  });

  it("returns error when current proof is invalid", () => {
    // Verifier returns false → proof invalid
    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(false),
    );

    const error = policy.validate(
      currentCommitment(),
      new Uint8Array(32).fill(1),
      newCommitmentBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error).not.toBeNull();
    expect(error!.code).toBe("INVALID_CURRENT_PROOF");
    expect(error!.message).toBe("Proof of current commitment knowledge is invalid");
  });

  it("checks encoding before identity element", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false, isIdentityElement: () => true }),
      createStubRotationProofVerifier(true),
    );

    const error = policy.validate(
      currentCommitment(),
      new Uint8Array(32).fill(1),
      newCommitmentBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error!.code).toBe("INVALID_ENCODING");
  });

  it("checks identity element before same commitment", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier({ isIdentityElement: () => true }),
      createStubRotationProofVerifier(true),
    );

    // Use same commitment bytes — identity check should fire first
    const current = currentCommitment();
    const error = policy.validate(
      current,
      new Uint8Array(32).fill(1),
      current.toBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error!.code).toBe("IDENTITY_ELEMENT");
  });

  it("all errors have LifecycleError name", () => {
    const policy = new RotationPolicy(
      createStubCommitmentVerifier({ isCanonical: () => false }),
      createStubRotationProofVerifier(true),
    );

    const error = policy.validate(
      currentCommitment(),
      new Uint8Array(32).fill(1),
      newCommitmentBytes(),
      new Uint8Array(32).fill(2),
    );

    expect(error!.name).toBe("LifecycleError");
  });

  it("same commitment check requires length match AND all bytes match (not just true)", () => {
    // Kill mutant: `true &&` instead of `newCommitmentBytes.length === currentBytes.length &&`
    // With `true`, any bytes would match the length check
    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(true),
    );

    // Different commitment (not same) should pass validation
    const error = policy.validate(
      currentCommitment(), // 0xab fill
      new Uint8Array(32).fill(1),
      newCommitmentBytes(0xcd), // different
      new Uint8Array(32).fill(2),
    );
    expect(error).toBeNull();
  });

  it("same commitment check uses every (not some) for byte comparison", () => {
    // Kill mutant: `.some((b, i) => b === currentBytes[i])` instead of `.every`
    // With `.some`, a single matching byte would trigger SAME_COMMITMENT
    const policy = new RotationPolicy(
      createStubCommitmentVerifier(),
      createStubRotationProofVerifier(true),
    );

    // Create a commitment that differs in most bytes but has one matching byte
    const current = currentCommitment(); // 0xab fill
    const newBytes = new Uint8Array(32).fill(0xcd);
    newBytes[0] = 0xab; // one byte matches

    const error = policy.validate(
      current,
      new Uint8Array(32).fill(1),
      newBytes,
      new Uint8Array(32).fill(2),
    );
    // With `.every`, only one byte matches out of 32 → NOT same commitment → null
    // With `.some`, at least one byte matches → wrongly triggers SAME_COMMITMENT
    expect(error).toBeNull();
  });
});
