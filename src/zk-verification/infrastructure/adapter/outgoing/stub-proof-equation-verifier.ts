// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ProofEquationVerifier } from "../../../domain/port/outgoing/proof-equation-verifier.js";

export class StubProofEquationVerifier implements ProofEquationVerifier {
  /** Number of times verify() has been called. */
  verifyCalls = 0;

  constructor(private result: boolean = true) {}

  verify(): boolean {
    this.verifyCalls++;
    return this.result;
  }

  setResult(result: boolean): void {
    this.result = result;
  }
}
