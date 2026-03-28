// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ExecutionSequencer, type SequencerSteps, type CryptoStep } from "../../../../packages/client-sdk/src/domain/service/execution-sequencer.js";

function step(name: string, log: string[]): CryptoStep<Uint8Array> {
  return { execute: async () => { log.push(name); return new Uint8Array(32); } };
}

describe("ExecutionSequencer", () => {
  const sequencer = new ExecutionSequencer();

  it("executes ALL steps in fixed order: AES → Argon2id → OPRF → proof → combine", async () => {
    const log: string[] = [];
    const steps: SequencerSteps = {
      aesGcm: step("aes", log),
      argon2id: step("argon2id", log),
      oprfHkdf: step("oprf", log),
      sigmaProof: step("proof", log),
      finalCombine: step("combine", log),
    };

    await sequencer.execute(steps);
    expect(log).toEqual(["aes", "argon2id", "oprf", "proof", "combine"]);
  });

  it("Tier 0 and Tier 1 produce identical execution order", async () => {
    const log0: string[] = [];
    const log1: string[] = [];

    // Tier 0: real Argon2id, dummy AES
    const tier0: SequencerSteps = {
      aesGcm: step("aes_dummy", log0),
      argon2id: step("argon2id_real", log0),
      oprfHkdf: step("oprf_real", log0),
      sigmaProof: step("proof_real", log0),
      finalCombine: step("combine", log0),
    };

    // Tier 1: real AES, dummy Argon2id
    const tier1: SequencerSteps = {
      aesGcm: step("aes_real", log1),
      argon2id: step("argon2id_dummy", log1),
      oprfHkdf: step("oprf_real", log1),
      sigmaProof: step("proof_real", log1),
      finalCombine: step("combine", log1),
    };

    await sequencer.execute(tier0);
    await sequencer.execute(tier1);

    // Same ORDER (the names differ but an external observer sees same sequence)
    expect(log0.length).toBe(log1.length);
    // AES is always first, Argon2id always second, etc.
    expect(log0[0]).toContain("aes");
    expect(log1[0]).toContain("aes");
    expect(log0[1]).toContain("argon2id");
    expect(log1[1]).toContain("argon2id");
  });

  it("returns results from all steps", async () => {
    const steps: SequencerSteps = {
      aesGcm: { execute: async () => new Uint8Array(32).fill(0xAA) },
      argon2id: { execute: async () => new Uint8Array(32).fill(0xBB) },
      oprfHkdf: { execute: async () => new Uint8Array(32).fill(0xCC) },
      sigmaProof: { execute: async () => new Uint8Array(32).fill(0xDD) },
      finalCombine: { execute: async () => new Uint8Array(32).fill(0xEE) },
    };

    const result = await sequencer.execute(steps);
    expect(result.aesResult[0]).toBe(0xAA);
    expect(result.argon2Result[0]).toBe(0xBB);
    expect(result.oprfResult[0]).toBe(0xCC);
    expect(result.proofResult[0]).toBe(0xDD);
    expect(result.finalHash[0]).toBe(0xEE);
  });

  it("finalCombine runs AFTER all other steps (data dependency uniform)", async () => {
    const log: string[] = [];
    const steps: SequencerSteps = {
      aesGcm: { execute: async () => { log.push("1"); return new Uint8Array(1); } },
      argon2id: { execute: async () => { log.push("2"); return new Uint8Array(1); } },
      oprfHkdf: { execute: async () => { log.push("3"); return new Uint8Array(1); } },
      sigmaProof: { execute: async () => { log.push("4"); return new Uint8Array(1); } },
      finalCombine: { execute: async () => { log.push("5"); return new Uint8Array(1); } },
    };

    await sequencer.execute(steps);
    expect(log).toEqual(["1", "2", "3", "4", "5"]);
    // finalCombine (5) is always last — same data dependency for all tiers
  });
});
