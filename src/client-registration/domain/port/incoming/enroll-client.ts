// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ProofOfPossessionData } from "../outgoing/proof-of-possession-verifier.js";

export interface EnrollClientRequest {
  clientIdentifier: string;
  commitmentBytes: Uint8Array;
  proofOfPossession: ProofOfPossessionData;
}

export type EnrollClientResponse =
  | { success: true; referenceId: string; clientIdentifier: string; recoveryWords?: readonly string[] }
  | { success: false; error: "enrollment_failed" };

export interface EnrollClient {
  execute(request: EnrollClientRequest): Promise<EnrollClientResponse>;
}
