// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  ProofOfPossessionVerifier,
  ProofOfPossessionData,
} from "../../../domain/port/outgoing/proof-of-possession-verifier.js";
import type { Commitment } from "../../../domain/model/commitment.js";

/**
 * Contract for the native crypto module used by the proof-of-possession verifier.
 * Delegates to the same verifyProofEquation function as NapiProofEquationVerifier,
 * but adds Fiat-Shamir challenge computation binding the client identifier.
 */
export interface NativeProofOfPossessionModule {
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

// Standard Ristretto255 generators (same as those used for Pedersen commitments)
const GENERATOR_G = Buffer.alloc(32, 0x01); // TODO: replace with actual Ristretto255 basepoint
const GENERATOR_H = Buffer.alloc(32, 0x02); // TODO: replace with actual Ristretto255 alternate generator

const DOMAIN_TAG = Buffer.from("2FApi-PoP-v1");

/**
 * Real implementation of ProofOfPossessionVerifier using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Verifies that the client knows the opening (s, r) of their Pedersen commitment
 * C = g^s * h^r by checking a Schnorr/Sigma proof with Fiat-Shamir challenge:
 *   challenge = H(domain_tag || g || h || C || A || clientIdentifier)
 *
 * All operations are constant-time in the native Rust layer.
 */
export class NapiProofOfPossessionVerifier implements ProofOfPossessionVerifier {
  private readonly generatorG: Buffer;
  private readonly generatorH: Buffer;

  constructor(
    private readonly nativeModule: NativeProofOfPossessionModule,
    generatorG?: Uint8Array,
    generatorH?: Uint8Array,
  ) {
    this.generatorG = generatorG ? Buffer.from(generatorG) : GENERATOR_G;
    this.generatorH = generatorH ? Buffer.from(generatorH) : GENERATOR_H;
  }

  verify(
    commitment: Commitment,
    proof: ProofOfPossessionData,
    clientIdentifier: string,
  ): boolean {
    try {
      // Reconstruct the Fiat-Shamir challenge from the transcript
      const commitmentBytes = Buffer.from(commitment.toBytes());
      const announcementBytes = Buffer.from(proof.announcement);
      const clientIdBytes = Buffer.from(clientIdentifier, "utf-8");

      const transcriptData = Buffer.concat([
        DOMAIN_TAG,
        this.generatorG,
        this.generatorH,
        commitmentBytes,
        announcementBytes,
        clientIdBytes,
      ]);

      const challenge = this.nativeModule.hashTranscript(transcriptData);

      return this.nativeModule.verifyProofEquation({
        generatorG: this.generatorG,
        generatorH: this.generatorH,
        commitment: commitmentBytes,
        announcement: announcementBytes,
        challenge,
        responseS: Buffer.from(proof.responseS),
        responseR: Buffer.from(proof.responseR),
      });
    } catch {
      // Native module errors are treated as verification failure
      return false;
    }
  }
}
