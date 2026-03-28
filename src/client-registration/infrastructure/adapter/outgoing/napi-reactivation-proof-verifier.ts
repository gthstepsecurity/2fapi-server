// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ReactivationProofVerifier } from "../../../application/usecase/reactivate-via-external.usecase.js";

/**
 * Contract for the native crypto module used by the reactivation proof verifier.
 */
export interface NativeReactivationProofModule {
  verifyProofEquation(params: {
    generatorG: Buffer;
    generatorH: Buffer;
    commitment: Buffer;
    announcement: Buffer;
    challenge: Buffer;
    responseS: Buffer;
    responseR: Buffer;
  }): boolean;
  hashTranscript(data: Buffer): Buffer;
}

const DOMAIN_TAG = Buffer.from("2FApi-Reactivation-v1");

/**
 * Minimum proof payload size: announcement (32) + responseS (32) + responseR (32) = 96 bytes.
 */
const PROOF_PAYLOAD_SIZE = 96;

/**
 * Real implementation of ReactivationProofVerifier using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Verifies proof of possession for a new commitment during admin-initiated
 * reactivation (BD08). Ensures the admin provides a valid cryptographic
 * proof to prevent impersonation.
 *
 * All operations are constant-time in the native Rust layer.
 */
export class NapiReactivationProofVerifier implements ReactivationProofVerifier {
  private readonly generatorG: Buffer;
  private readonly generatorH: Buffer;

  constructor(
    private readonly nativeModule: NativeReactivationProofModule,
    generatorG?: Uint8Array,
    generatorH?: Uint8Array,
  ) {
    this.generatorG = generatorG ? Buffer.from(generatorG) : Buffer.alloc(32, 0x01);
    this.generatorH = generatorH ? Buffer.from(generatorH) : Buffer.alloc(32, 0x02);
  }

  verify(newCommitmentBytes: Uint8Array, proofBytes: Uint8Array): boolean {
    try {
      if (proofBytes.length < PROOF_PAYLOAD_SIZE) {
        return false;
      }

      // Parse proof bytes: [announcement(32) | responseS(32) | responseR(32)]
      const announcement = Buffer.from(proofBytes.subarray(0, 32));
      const responseS = Buffer.from(proofBytes.subarray(32, 64));
      const responseR = Buffer.from(proofBytes.subarray(64, 96));
      const commitmentBuf = Buffer.from(newCommitmentBytes);

      const transcript = Buffer.concat([
        DOMAIN_TAG,
        this.generatorG,
        this.generatorH,
        commitmentBuf,
        announcement,
      ]);
      const challenge = this.nativeModule.hashTranscript(transcript);

      return this.nativeModule.verifyProofEquation({
        generatorG: this.generatorG,
        generatorH: this.generatorH,
        commitment: commitmentBuf,
        announcement,
        challenge,
        responseS,
        responseR,
      });
    } catch {
      return false;
    }
  }
}
