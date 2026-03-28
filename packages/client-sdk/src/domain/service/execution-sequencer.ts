// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: enforces a FIXED execution order for all crypto operations,
 * regardless of authentication tier.
 *
 * Even with timing normalization (500ms total), the MICRO-PATTERN of CPU
 * activity within the window differs by tier:
 *   Tier 0: [Argon2id 498ms] → [AES-GCM 1ms] → [proof 1ms]
 *   Tier 1: [AES-GCM 1ms] → [Argon2id 498ms] → [proof 1ms]
 *
 * A DPA (Differential Power Analysis) observer with an oscilloscope on
 * the power rail could detect the order difference.
 *
 * Fix: ALL tiers execute operations in the SAME fixed order:
 *   1. AES-GCM (real or dummy)     — always first
 *   2. Argon2id (real or dummy)     — always second
 *   3. OPRF + HKDF                  — always third
 *   4. Sigma proof                  — always fourth
 *
 * The output of each step is ALWAYS fed into the next (real or dummy HKDF),
 * so the data dependency pattern is identical.
 */

export interface CryptoStep<T> {
  execute(): Promise<T>;
}

export class ExecutionSequencer {
  /**
   * Execute all crypto steps in a fixed order, regardless of which are "real."
   * Steps that aren't needed for this tier execute with dummy data but
   * the SAME functions run in the SAME order.
   */
  async execute(steps: SequencerSteps): Promise<SequencerResult> {
    // Step 1: AES-GCM (always first — real vault decrypt or dummy)
    const aesResult = await steps.aesGcm.execute();

    // Step 2: Argon2id (always second — real derivation or dummy)
    const argon2Result = await steps.argon2id.execute();

    // Step 3: OPRF + HKDF (always third)
    const oprfResult = await steps.oprfHkdf.execute();

    // Step 4: Sigma proof (always fourth)
    const proofResult = await steps.sigmaProof.execute();

    // Step 5: ALWAYS combine all results through a final HKDF
    // Even dummy results feed into a real HKDF call (discarded if dummy).
    // This ensures the data dependency graph is IDENTICAL for all tiers.
    const finalHash = await steps.finalCombine.execute();

    return {
      aesResult,
      argon2Result,
      oprfResult,
      proofResult,
      finalHash,
    };
  }
}

export interface SequencerSteps {
  readonly aesGcm: CryptoStep<Uint8Array>;       // vault decrypt or dummy
  readonly argon2id: CryptoStep<Uint8Array>;      // real derivation or dummy
  readonly oprfHkdf: CryptoStep<Uint8Array>;      // OPRF unblind + HKDF
  readonly sigmaProof: CryptoStep<Uint8Array>;    // proof generation
  readonly finalCombine: CryptoStep<Uint8Array>;  // combine all outputs via HKDF
}

export interface SequencerResult {
  readonly aesResult: Uint8Array;
  readonly argon2Result: Uint8Array;
  readonly oprfResult: Uint8Array;
  readonly proofResult: Uint8Array;
  readonly finalHash: Uint8Array;
}
