// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  ProofOfPossessionVerifier,
  ProofOfPossessionData,
} from "../../../domain/port/outgoing/proof-of-possession-verifier.js";
import type { Commitment } from "../../../domain/model/commitment.js";

export class StubProofOfPossessionVerifier implements ProofOfPossessionVerifier {
  constructor(private readonly validResult: boolean = true) {}

  verify(
    _commitment: Commitment,
    _proof: ProofOfPossessionData,
    _clientIdentifier: string,
  ): boolean {
    return this.validResult;
  }
}
