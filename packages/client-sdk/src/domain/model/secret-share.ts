// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "./result.js";

/**
 * Value object: one share of a 2-of-2 additive secret sharing.
 *
 * The full Pedersen secret (s, r) is split: s = s1 + s2, r = r1 + r2.
 * This share holds (s_i, r_i) — half the secret.
 * The full secret NEVER exists in cleartext on any single machine.
 */
export class SecretShare {
  private constructor(
    readonly shareS: Uint8Array,
    readonly shareR: Uint8Array,
    readonly party: "client" | "server",
  ) {}

  static create(shareS: Uint8Array, shareR: Uint8Array, party: "client" | "server"): SecretShare {
    if (shareS.length !== 32 || shareR.length !== 32) {
      throw new Error("Share scalars must be 32 bytes");
    }
    return new SecretShare(shareS, shareR, party);
  }

  /**
   * Compute a partial Sigma response: z_s_i = k_s + c · s_i (client)
   * or z_s_i = c · s_i (server, no nonce).
   *
   * This is a LINEAR operation — the core of why secret sharing works
   * for Sigma proofs without ever reconstructing the secret.
   */
  computePartialResponse(challenge: Uint8Array, nonce_s?: Uint8Array, nonce_r?: Uint8Array): PartialProofResponse {
    // The actual scalar arithmetic is done in WASM/NAPI.
    // This model represents the STRUCTURE, not the computation.
    return {
      z_s_partial: this.shareS, // placeholder — real impl in WASM
      z_r_partial: this.shareR,
      party: this.party,
    };
  }
}

export interface PartialProofResponse {
  readonly z_s_partial: Uint8Array;
  readonly z_r_partial: Uint8Array;
  readonly party: "client" | "server";
}
