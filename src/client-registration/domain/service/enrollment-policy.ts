// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CommitmentVerifier } from "../port/outgoing/commitment-verifier.js";
import type { ProofOfPossessionVerifier } from "../port/outgoing/proof-of-possession-verifier.js";
import type { ProofOfPossessionData } from "../port/outgoing/proof-of-possession-verifier.js";
import { Commitment } from "../model/commitment.js";
// Note: deep import path — will be replaced by path alias (@shared/errors) when tsconfig paths are configured
import { EnrollmentError } from "../../../shared/errors.js";

export class EnrollmentPolicy {
  constructor(
    private readonly commitmentVerifier: CommitmentVerifier,
    private readonly proofVerifier: ProofOfPossessionVerifier,
  ) {}

  validate(
    commitmentBytes: Uint8Array | undefined,
    proof: ProofOfPossessionData | undefined,
    clientIdentifier: string,
  ): EnrollmentError | null {
    if (commitmentBytes === undefined || commitmentBytes === null) {
      return new EnrollmentError("MISSING_COMMITMENT", "Commitment bytes are required");
    }
    if (!this.commitmentVerifier.isCanonical(commitmentBytes)) {
      return new EnrollmentError("INVALID_ENCODING", "Commitment encoding is not canonical");
    }
    if (!this.commitmentVerifier.isValidGroupElement(commitmentBytes)) {
      return new EnrollmentError("INVALID_GROUP_ELEMENT", "Commitment is not a valid group element");
    }
    if (this.commitmentVerifier.isIdentityElement(commitmentBytes)) {
      return new EnrollmentError("IDENTITY_ELEMENT", "Commitment must not be the identity element");
    }
    if (proof === undefined || proof === null) {
      return new EnrollmentError("MISSING_PROOF", "Proof of possession is required");
    }
    const commitment = Commitment.fromBytes(commitmentBytes);
    if (!this.proofVerifier.verify(commitment, proof, clientIdentifier)) {
      return new EnrollmentError("INVALID_PROOF", "Proof of possession is invalid");
    }
    return null;
  }
}
