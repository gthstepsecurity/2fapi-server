// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { BatchVerificationService } from "../../../src/zk-verification/domain/service/batch-verification-service.js";
import type { BatchProofVerifier } from "../../../src/zk-verification/domain/port/outgoing/batch-proof-verifier.js";
import type { VerifyProof, VerifyProofRequest, VerifyProofResponse } from "../../../src/zk-verification/domain/port/incoming/verify-proof.js";
import { validVerifyProofRequest } from "../../helpers/verification-test-helpers.js";

function createStubVerifyProof(results: VerifyProofResponse[]): VerifyProof {
  let callIndex = 0;
  return {
    async execute(): Promise<VerifyProofResponse> {
      const result = results[callIndex]!;
      callIndex++;
      return result;
    },
  };
}

describe("BatchVerificationService", () => {
  it("should verify a single proof successfully", async () => {
    const verifyProof = createStubVerifyProof([
      { success: true, clientIdentifier: "alice" },
    ]);
    const service = new BatchVerificationService(verifyProof);

    const results = await service.verifyBatch([validVerifyProofRequest()]);

    expect(results).toHaveLength(1);
    expect(results[0]!.success).toBe(true);
  });

  it("should verify multiple proofs independently", async () => {
    const verifyProof = createStubVerifyProof([
      { success: true, clientIdentifier: "alice" },
      { success: false, error: "verification_refused" },
      { success: true, clientIdentifier: "charlie" },
    ]);
    const service = new BatchVerificationService(verifyProof);

    const requests = [
      validVerifyProofRequest({ clientIdentifier: "alice" }),
      validVerifyProofRequest({ clientIdentifier: "bob" }),
      validVerifyProofRequest({ clientIdentifier: "charlie" }),
    ];
    const results = await service.verifyBatch(requests);

    expect(results).toHaveLength(3);
    expect(results[0]!.success).toBe(true);
    expect(results[1]!.success).toBe(false);
    expect(results[2]!.success).toBe(true);
  });

  it("should return empty array for empty batch", async () => {
    const verifyProof = createStubVerifyProof([]);
    const service = new BatchVerificationService(verifyProof);

    const results = await service.verifyBatch([]);

    expect(results).toHaveLength(0);
  });

  it("should not let one invalid proof affect others in batch", async () => {
    const verifyProof = createStubVerifyProof([
      { success: true, clientIdentifier: "alice" },
      { success: false, error: "verification_refused" },
      { success: true, clientIdentifier: "charlie" },
      { success: true, clientIdentifier: "dave" },
      { success: false, error: "verification_refused" },
    ]);
    const service = new BatchVerificationService(verifyProof);

    const requests = Array.from({ length: 5 }, (_, i) =>
      validVerifyProofRequest({ clientIdentifier: `client-${i}` }),
    );
    const results = await service.verifyBatch(requests);

    expect(results).toHaveLength(5);
    // Valid proofs pass regardless of invalid ones in the batch
    expect(results[0]!.success).toBe(true);
    expect(results[2]!.success).toBe(true);
    expect(results[3]!.success).toBe(true);
    // Invalid proofs still fail
    expect(results[1]!.success).toBe(false);
    expect(results[4]!.success).toBe(false);
  });
});
