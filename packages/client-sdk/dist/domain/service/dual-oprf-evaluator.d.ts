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
export declare class DualOprfEvaluator {
    private readonly hsmA;
    private readonly hsmB;
    constructor(hsmA: OprfHsmEndpoint, hsmB: OprfHsmEndpoint);
    /**
     * Evaluate OPRF across two HSMs in parallel.
     * Returns E_total = E_A + E_B where E_X = key_X · B.
     * The client unblinds: U = r⁻¹ · E_total = (key_A + key_B) · H(password).
     */
    evaluate(blindedPoint: Uint8Array): Promise<DualOprfResult>;
}
export interface OprfHsmEndpoint {
    readonly name: string;
    readonly vendor: string;
    readonly jurisdiction: string;
    evaluate(blindedPoint: Uint8Array): Promise<HsmEvalResult>;
}
export type HsmEvalResult = {
    readonly status: "ok";
    readonly evaluated: Uint8Array;
} | {
    readonly status: "error";
    readonly message: string;
};
export type DualOprfResult = {
    readonly status: "ok";
    readonly evaluatedA: Uint8Array;
    readonly evaluatedB: Uint8Array;
} | {
    readonly status: "error";
    readonly message: string;
    readonly failedHsm: string;
};
//# sourceMappingURL=dual-oprf-evaluator.d.ts.map
