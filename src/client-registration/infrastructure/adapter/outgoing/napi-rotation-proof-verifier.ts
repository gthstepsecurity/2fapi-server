// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Commitment } from "../../../domain/model/commitment.js";
import type { RotationProofVerifier } from "../../../domain/port/outgoing/rotation-proof-verifier.js";

/**
 * Contract for the native crypto module used by the rotation proof verifier.
 */
export interface NativeRotationProofModule {
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

const DOMAIN_TAG_CURRENT = Buffer.from("2FApi-Rotation-Current-v1");
const DOMAIN_TAG_NEW = Buffer.from("2FApi-Rotation-New-v1");

/**
 * Minimum proof payload size: announcement (32) + responseS (32) + responseR (32) = 96 bytes.
 */
const PROOF_PAYLOAD_SIZE = 96;

/**
 * Real implementation of RotationProofVerifier using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Verifies two proofs for commitment rotation:
 * 1. Proof of knowledge of the current commitment opening
 * 2. Proof of possession for the new commitment
 *
 * All operations are constant-time in the native Rust layer.
 */
export class NapiRotationProofVerifier implements RotationProofVerifier {
  private readonly generatorG: Buffer;
  private readonly generatorH: Buffer;

  constructor(
    private readonly nativeModule: NativeRotationProofModule,
    generatorG?: Uint8Array,
    generatorH?: Uint8Array,
  ) {
    this.generatorG = generatorG ? Buffer.from(generatorG) : Buffer.alloc(32, 0x01);
    this.generatorH = generatorH ? Buffer.from(generatorH) : Buffer.alloc(32, 0x02);
  }

  verify(
    currentCommitment: Commitment,
    currentProofBytes: Uint8Array,
    newCommitment: Commitment,
    newProofBytes: Uint8Array,
  ): boolean {
    try {
      if (currentProofBytes.length < PROOF_PAYLOAD_SIZE || newProofBytes.length < PROOF_PAYLOAD_SIZE) {
        return false;
      }

      // Parse proof bytes: [announcement(32) | responseS(32) | responseR(32)]
      const currentAnnouncement = Buffer.from(currentProofBytes.subarray(0, 32));
      const currentResponseS = Buffer.from(currentProofBytes.subarray(32, 64));
      const currentResponseR = Buffer.from(currentProofBytes.subarray(64, 96));

      const newAnnouncement = Buffer.from(newProofBytes.subarray(0, 32));
      const newResponseS = Buffer.from(newProofBytes.subarray(32, 64));
      const newResponseR = Buffer.from(newProofBytes.subarray(64, 96));

      const currentCommitmentBuf = Buffer.from(currentCommitment.toBytes());
      const newCommitmentBuf = Buffer.from(newCommitment.toBytes());

      // Verify proof of current commitment knowledge
      const currentTranscript = Buffer.concat([
        DOMAIN_TAG_CURRENT,
        this.generatorG,
        this.generatorH,
        currentCommitmentBuf,
        currentAnnouncement,
      ]);
      const currentChallenge = this.nativeModule.hashTranscript(currentTranscript);

      const currentValid = this.nativeModule.verifyProofEquation({
        generatorG: this.generatorG,
        generatorH: this.generatorH,
        commitment: currentCommitmentBuf,
        announcement: currentAnnouncement,
        challenge: currentChallenge,
        responseS: currentResponseS,
        responseR: currentResponseR,
      });

      // Verify proof of new commitment possession
      const newTranscript = Buffer.concat([
        DOMAIN_TAG_NEW,
        this.generatorG,
        this.generatorH,
        newCommitmentBuf,
        newAnnouncement,
      ]);
      const newChallenge = this.nativeModule.hashTranscript(newTranscript);

      const newValid = this.nativeModule.verifyProofEquation({
        generatorG: this.generatorG,
        generatorH: this.generatorH,
        commitment: newCommitmentBuf,
        announcement: newAnnouncement,
        challenge: newChallenge,
        responseS: newResponseS,
        responseR: newResponseR,
      });

      // Both proofs must be valid — use bitwise AND to avoid short-circuit
      // timing leaks. Both verifications are always executed above,
      // and the result combination is constant-time.
      const bothValid = (currentValid ? 1 : 0) & (newValid ? 1 : 0);
      return bothValid === 1;
    } catch {
      return false;
    }
  }
}
