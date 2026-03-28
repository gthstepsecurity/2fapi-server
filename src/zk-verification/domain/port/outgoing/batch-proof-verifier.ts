// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VerifyProofRequest, VerifyProofResponse } from "../incoming/verify-proof.js";

/**
 * Verifies a batch of proofs. Each proof is independently judged:
 * one invalid proof in the batch does not affect the others.
 */
export interface BatchProofVerifier {
  verifyBatch(
    requests: ReadonlyArray<VerifyProofRequest>,
  ): Promise<ReadonlyArray<VerifyProofResponse>>;
}
