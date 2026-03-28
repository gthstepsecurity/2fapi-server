// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CommitmentVerifier } from "../port/outgoing/commitment-verifier.js";
import type { RotationProofVerifier } from "../port/outgoing/rotation-proof-verifier.js";
import type { Commitment } from "../model/commitment.js";
import { Commitment as CommitmentImpl } from "../model/commitment.js";
import { LifecycleError } from "../../../shared/errors.js";

export class RotationPolicy {
  constructor(
    private readonly commitmentVerifier: CommitmentVerifier,
    private readonly rotationProofVerifier: RotationProofVerifier,
  ) {}

  validate(
    currentCommitment: Commitment,
    currentProofBytes: Uint8Array,
    newCommitmentBytes: Uint8Array,
    newCommitmentProofBytes: Uint8Array,
  ): LifecycleError | null {
    if (!this.commitmentVerifier.isCanonical(newCommitmentBytes)) {
      return new LifecycleError("INVALID_ENCODING", "New commitment encoding is not canonical");
    }

    if (this.commitmentVerifier.isIdentityElement(newCommitmentBytes)) {
      return new LifecycleError("IDENTITY_ELEMENT", "New commitment must not be the identity element");
    }

    // Check if new commitment equals current (byte-exact comparison)
    const currentBytes = currentCommitment.toBytes();
    if (
      newCommitmentBytes.length === currentBytes.length &&
      newCommitmentBytes.every((b, i) => b === currentBytes[i])
    ) {
      return new LifecycleError("SAME_COMMITMENT", "New commitment must differ from the current commitment");
    }

    // Construct new Commitment VO for proof verification
    let newCommitment: Commitment;
    try {
      newCommitment = CommitmentImpl.fromBytes(newCommitmentBytes);
    } catch {
      return new LifecycleError("INVALID_ENCODING", "New commitment bytes are invalid");
    }

    if (!this.rotationProofVerifier.verify(
      currentCommitment,
      currentProofBytes,
      newCommitment,
      newCommitmentProofBytes,
    )) {
      return new LifecycleError("INVALID_CURRENT_PROOF", "Proof of current commitment knowledge is invalid");
    }

    return null;
  }
}
