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
export declare class ExecutionSequencer {
    /**
     * Execute all crypto steps in a fixed order, regardless of which are "real."
     * Steps that aren't needed for this tier execute with dummy data but
     * the SAME functions run in the SAME order.
     */
    execute(steps: SequencerSteps): Promise<SequencerResult>;
}
export interface SequencerSteps {
    readonly aesGcm: CryptoStep<Uint8Array>;
    readonly argon2id: CryptoStep<Uint8Array>;
    readonly oprfHkdf: CryptoStep<Uint8Array>;
    readonly sigmaProof: CryptoStep<Uint8Array>;
    readonly finalCombine: CryptoStep<Uint8Array>;
}
export interface SequencerResult {
    readonly aesResult: Uint8Array;
    readonly argon2Result: Uint8Array;
    readonly oprfResult: Uint8Array;
    readonly proofResult: Uint8Array;
    readonly finalHash: Uint8Array;
}
//# sourceMappingURL=execution-sequencer.d.ts.map
