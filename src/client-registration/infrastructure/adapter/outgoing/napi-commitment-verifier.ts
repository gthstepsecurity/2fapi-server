// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CommitmentVerifier } from "../../../domain/port/outgoing/commitment-verifier.js";

/**
 * Contract for the native crypto module used by the commitment verifier.
 */
export interface NativeCommitmentModule {
  isCanonicalPoint(bytes: Buffer): boolean;
  isIdentityPoint(bytes: Buffer): boolean;
}

/**
 * Real implementation of CommitmentVerifier using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Validates Pedersen commitments: canonical encoding, group membership,
 * and identity element rejection — all in Ristretto255.
 */
export class NapiCommitmentVerifier implements CommitmentVerifier {
  constructor(private readonly nativeModule: NativeCommitmentModule) {}

  isCanonical(bytes: Uint8Array): boolean {
    try {
      // A canonical point encoding must be exactly 32 bytes and decompress
      // to a valid Ristretto255 point. The native module handles both checks.
      return this.nativeModule.isCanonicalPoint(Buffer.from(bytes));
    } catch {
      return false;
    }
  }

  isValidGroupElement(bytes: Uint8Array): boolean {
    try {
      // In Ristretto255, if isCanonicalPoint returns true then the bytes
      // decode to a valid group element. This is a property of the Ristretto
      // encoding: there are no non-group-element canonical encodings.
      return this.nativeModule.isCanonicalPoint(Buffer.from(bytes));
    } catch {
      return false;
    }
  }

  isIdentityElement(bytes: Uint8Array): boolean {
    try {
      return this.nativeModule.isIdentityPoint(Buffer.from(bytes));
    } catch {
      return false;
    }
  }
}
