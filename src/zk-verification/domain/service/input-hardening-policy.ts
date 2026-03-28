// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const MAX_PAYLOAD_SIZE = 1024;
const PROOF_BYTE_LENGTH = 96;

export type InputHardeningErrorCode =
  | "PAYLOAD_TOO_LARGE"
  | "IDENTITY_PROOF"
  | "NON_CANONICAL_PROOF";

export class InputHardeningError {
  constructor(
    readonly code: InputHardeningErrorCode,
    readonly message: string,
  ) {}
}

/**
 * Domain service for payload-level input hardening.
 * Validates proof payloads before they enter the verification pipeline:
 * - Payload size limit (max 1024 bytes)
 * - All-zeros proof rejected (identity point)
 * - All-0xFF proof rejected (non-canonical encoding)
 */
export class InputHardeningPolicy {
  validate(payload: Uint8Array): InputHardeningError | null {
    // 1. Payload size limit
    if (payload.length > MAX_PAYLOAD_SIZE) {
      return new InputHardeningError(
        "PAYLOAD_TOO_LARGE",
        `Payload exceeds maximum size of ${MAX_PAYLOAD_SIZE} bytes`,
      );
    }

    // The following checks only apply to proof-sized payloads
    if (payload.length !== PROOF_BYTE_LENGTH) {
      return null;
    }

    // 2. All-zeros proof (identity point as announcement)
    if (this.isAllZeros(payload)) {
      return new InputHardeningError(
        "IDENTITY_PROOF",
        "Proof consists entirely of zero bytes (identity point)",
      );
    }

    // 3. All-0xFF proof (non-canonical encoding)
    if (this.isAllOnes(payload)) {
      return new InputHardeningError(
        "NON_CANONICAL_PROOF",
        "Proof consists entirely of 0xFF bytes (non-canonical)",
      );
    }

    return null;
  }

  private isAllZeros(bytes: Uint8Array): boolean {
    let acc = 0;
    for (let i = 0; i < bytes.length; i++) {
      acc |= bytes[i]!;
    }
    return acc === 0;
  }

  private isAllOnes(bytes: Uint8Array): boolean {
    let acc = 0;
    for (let i = 0; i < bytes.length; i++) {
      acc |= bytes[i]! ^ 0xff;
    }
    return acc === 0;
  }
}
