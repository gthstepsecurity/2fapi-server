// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: dual-HSM OPRF evaluation (R16-02 fix).
 *
 * Splits the OPRF evaluation across two independent HSMs from different
 * manufacturers/jurisdictions. The effective OPRF key = key_A + key_B.
 * Neither HSM knows the effective key. Compromising one HSM reveals
 * only half the key — the vault remains secure.
 *
 * This is the "nuclear launch code" model for cryptographic operations.
 */
export class DualOprfEvaluator {
  constructor(
    private readonly hsmA: OprfHsmEndpoint,
    private readonly hsmB: OprfHsmEndpoint,
  ) {}

  /**
   * Evaluate OPRF across two HSMs in parallel.
   * Returns E_total = E_A + E_B where E_X = key_X · B.
   * The client unblinds: U = r⁻¹ · E_total = (key_A + key_B) · H(password).
   */
  async evaluate(blindedPoint: Uint8Array): Promise<DualOprfResult> {
    // Evaluate in PARALLEL (both HSMs receive the same blinded point)
    const [resultA, resultB] = await Promise.all([
      this.hsmA.evaluate(blindedPoint),
      this.hsmB.evaluate(blindedPoint),
    ]);

    if (resultA.status !== "ok" || resultB.status !== "ok") {
      // If one HSM fails, we CANNOT proceed (both are required)
      const failedHsm = resultA.status !== "ok" ? "A" : "B";
      return {
        status: "error",
        message: `HSM ${failedHsm} evaluation failed`,
        failedHsm,
      };
    }

    // Combine: E_total = E_A + E_B (point addition)
    // In production, this is done in WASM: addPoints(E_A, E_B)
    // For the domain layer, we return both for the crypto engine to combine
    return {
      status: "ok",
      evaluatedA: resultA.evaluated,
      evaluatedB: resultB.evaluated,
    };
  }
}

export interface OprfHsmEndpoint {
  readonly name: string;
  readonly vendor: string;
  readonly jurisdiction: string;
  evaluate(blindedPoint: Uint8Array): Promise<HsmEvalResult>;
}

export type HsmEvalResult =
  | { readonly status: "ok"; readonly evaluated: Uint8Array }
  | { readonly status: "error"; readonly message: string };

export type DualOprfResult =
  | { readonly status: "ok"; readonly evaluatedA: Uint8Array; readonly evaluatedB: Uint8Array }
  | { readonly status: "error"; readonly message: string; readonly failedHsm: string };
