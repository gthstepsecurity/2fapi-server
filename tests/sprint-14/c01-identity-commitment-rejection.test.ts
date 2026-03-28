// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  ProofVerificationPolicy,
  ProofVerificationError,
} from "../../src/zk-verification/domain/service/proof-verification-policy.js";
import type { ElementValidator } from "../../src/zk-verification/domain/port/outgoing/element-validator.js";
import type { CommitmentInfo } from "../../src/zk-verification/domain/port/outgoing/commitment-lookup.js";

function createAllValidElementValidator(): ElementValidator {
  return {
    isCanonicalScalar: () => true,
    isCanonicalPoint: () => true,
  };
}

function validProofBytes(): Uint8Array {
  const bytes = new Uint8Array(96);
  bytes[0] = 0x01; // non-identity announcement
  bytes[32] = 0x02;
  bytes[64] = 0x03;
  return bytes;
}

const PROTOCOL_TAG = "2FApi-v1.0-Sigma";

describe("C-01: Identity commitment must be rejected", () => {
  it("should return INVALID_ENCODING when commitment is the identity element (all zeros)", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    // Commitment is the identity: all zeros
    const identityCommitment: CommitmentInfo = {
      commitment: new Uint8Array(32).fill(0x00),
      clientStatus: "active",
    };

    const result = policy.validate({
      commitmentInfo: identityCommitment,
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeInstanceOf(ProofVerificationError);
    expect(result!.code).toBe("INVALID_ENCODING");
    expect(result!.message).toContain("identity");
  });

  it("should accept a non-identity commitment", () => {
    const policy = new ProofVerificationPolicy(createAllValidElementValidator());

    const validCommitment: CommitmentInfo = {
      commitment: new Uint8Array(32).fill(0xaa),
      clientStatus: "active",
    };

    const result = policy.validate({
      commitmentInfo: validCommitment,
      domainSeparationTag: PROTOCOL_TAG,
      proofBytes: validProofBytes(),
    });

    expect(result).toBeNull();
  });
});
