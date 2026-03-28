// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ElementValidator } from "../port/outgoing/element-validator.js";
import type { CommitmentInfo } from "../port/outgoing/commitment-lookup.js";
import { PROOF_BYTE_LENGTH } from "../model/proof.js";
const ELEMENT_BYTE_LENGTH = 32;
const PROTOCOL_TAG = "2FApi-v1.0-Sigma";

export type ProofVerificationErrorCode =
  | "CLIENT_NOT_FOUND"
  | "CLIENT_REVOKED"
  | "INVALID_TAG"
  | "INVALID_ENCODING";

export class ProofVerificationError extends Error {
  constructor(
    readonly code: ProofVerificationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ProofVerificationError";
  }
}

export interface VerificationPreconditions {
  readonly commitmentInfo: CommitmentInfo | null;
  readonly domainSeparationTag: string;
  readonly proofBytes: Uint8Array;
}

export class ProofVerificationPolicy {
  constructor(private readonly elementValidator: ElementValidator) {}

  validate(preconditions: VerificationPreconditions): ProofVerificationError | null {
    // 1. Client must exist
    if (preconditions.commitmentInfo === null) {
      return new ProofVerificationError("CLIENT_NOT_FOUND", "Client not found");
    }

    // 2. Client must be active (not revoked or unknown)
    if (preconditions.commitmentInfo.clientStatus !== "active") {
      return new ProofVerificationError("CLIENT_REVOKED", "Client is not active");
    }

    // 3. Commitment must not be the identity element (all zeros)
    if (this.isIdentityCommitment(preconditions.commitmentInfo.commitment)) {
      return new ProofVerificationError("INVALID_ENCODING", "Commitment must not be the identity element");
    }

    // 4. Domain separation tag must match protocol
    if (preconditions.domainSeparationTag !== PROTOCOL_TAG) {
      return new ProofVerificationError("INVALID_TAG", "Domain separation tag does not match protocol");
    }

    // 4. Proof encoding validation
    const encodingError = this.validateProofEncoding(preconditions.proofBytes);
    if (encodingError !== null) {
      return encodingError;
    }

    return null;
  }

  private isIdentityCommitment(commitment: Uint8Array): boolean {
    let acc = 0;
    for (let i = 0; i < commitment.length; i++) {
      acc |= commitment[i]!;
    }
    return acc === 0;
  }

  private validateProofEncoding(proofBytes: Uint8Array): ProofVerificationError | null {
    // Must be exactly 96 bytes
    if (proofBytes.length !== PROOF_BYTE_LENGTH) {
      return new ProofVerificationError("INVALID_ENCODING", `Proof must be exactly ${PROOF_BYTE_LENGTH} bytes`);
    }

    const announcementBytes = proofBytes.slice(0, ELEMENT_BYTE_LENGTH);
    const responseSBytes = proofBytes.slice(ELEMENT_BYTE_LENGTH, 2 * ELEMENT_BYTE_LENGTH);
    const responseRBytes = proofBytes.slice(2 * ELEMENT_BYTE_LENGTH, 3 * ELEMENT_BYTE_LENGTH);

    // Announcement must be a canonical point
    if (!this.elementValidator.isCanonicalPoint(announcementBytes)) {
      return new ProofVerificationError("INVALID_ENCODING", "Announcement point is not canonical");
    }

    // Announcement must not be the identity element (constant-time check)
    let acc = 0;
    for (let i = 0; i < ELEMENT_BYTE_LENGTH; i++) {
      acc |= announcementBytes[i]!;
    }
    if (acc === 0) {
      return new ProofVerificationError("INVALID_ENCODING", "Announcement must not be the identity element");
    }

    // Response scalars must be canonical
    if (!this.elementValidator.isCanonicalScalar(responseSBytes)) {
      return new ProofVerificationError("INVALID_ENCODING", "Response scalar s is not canonical");
    }

    if (!this.elementValidator.isCanonicalScalar(responseRBytes)) {
      return new ProofVerificationError("INVALID_ENCODING", "Response scalar r is not canonical");
    }

    return null;
  }
}
