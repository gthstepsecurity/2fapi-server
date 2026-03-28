// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CommitmentVerifier } from "../../../domain/port/outgoing/commitment-verifier.js";

export interface StubCommitmentVerifierConfig {
  isCanonical?: boolean;
  isValidGroupElement?: boolean;
  isIdentityElement?: boolean;
}

export class StubCommitmentVerifier implements CommitmentVerifier {
  private readonly config: Required<StubCommitmentVerifierConfig>;

  constructor(config: StubCommitmentVerifierConfig = {}) {
    this.config = {
      isCanonical: config.isCanonical ?? true,
      isValidGroupElement: config.isValidGroupElement ?? true,
      isIdentityElement: config.isIdentityElement ?? false,
    };
  }

  isCanonical(_bytes: Uint8Array): boolean {
    return this.config.isCanonical;
  }

  isValidGroupElement(_bytes: Uint8Array): boolean {
    return this.config.isValidGroupElement;
  }

  isIdentityElement(_bytes: Uint8Array): boolean {
    return this.config.isIdentityElement;
  }
}
