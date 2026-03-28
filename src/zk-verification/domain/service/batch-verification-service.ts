// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VerifyProof, VerifyProofRequest, VerifyProofResponse } from "../port/incoming/verify-proof.js";
import type { BatchProofVerifier } from "../port/outgoing/batch-proof-verifier.js";

/**
 * Domain service that verifies N proofs by delegating each
 * to the single-proof VerifyProof use case.
 * Each proof is independently judged: one invalid proof
 * does not affect others in the batch.
 */
export class BatchVerificationService implements BatchProofVerifier {
  constructor(private readonly verifyProof: VerifyProof) {}

  async verifyBatch(
    requests: ReadonlyArray<VerifyProofRequest>,
  ): Promise<ReadonlyArray<VerifyProofResponse>> {
    const results = await Promise.all(
      requests.map((request) => this.verifyProof.execute(request)),
    );
    return results;
  }
}
