// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Commitment } from "../../../domain/model/commitment.js";
import type { RotationProofVerifier } from "../../../domain/port/outgoing/rotation-proof-verifier.js";

export class StubRotationProofVerifier implements RotationProofVerifier {
  constructor(private readonly alwaysValid: boolean = true) {}

  verify(
    _currentCommitment: Commitment,
    _currentProofBytes: Uint8Array,
    _newCommitment: Commitment,
    _newProofBytes: Uint8Array,
  ): boolean {
    return this.alwaysValid;
  }
}
