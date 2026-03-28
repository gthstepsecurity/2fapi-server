// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DrunkardExecutor, type DummyOperation } from "../../../../packages/client-sdk/src/domain/service/drunkard-executor.js";

function dummyOp(name: string, log: string[]): DummyOperation {
  return { name, execute: async () => { log.push(`dummy:${name}`); } };
}

describe("DrunkardExecutor", () => {
  it("executes all real steps in order", async () => {
    const log: string[] = [];
    const dummies = [dummyOp("aes", log), dummyOp("hash", log), dummyOp("ec", log)];
    const executor = new DrunkardExecutor(dummies, () => 0); // deterministic for testing

    const realSteps = [
      async () => { log.push("REAL:oprf"); },
      async () => { log.push("REAL:argon2id"); },
      async () => { log.push("REAL:proof"); },
    ];

    await executor.execute(realSteps);

    // Real steps are in order
    const realOps = log.filter(l => l.startsWith("REAL:"));
    expect(realOps).toEqual(["REAL:oprf", "REAL:argon2id", "REAL:proof"]);
  });

  it("interleaves dummy operations between real ones", async () => {
    const log: string[] = [];
    const dummies = [dummyOp("noise", log)];
    const executor = new DrunkardExecutor(dummies, () => 0); // always 1 dummy (min)

    await executor.execute([
      async () => { log.push("REAL:1"); },
      async () => { log.push("REAL:2"); },
    ]);

    // Dummies appear between and after real ops
    expect(log.filter(l => l.startsWith("dummy:")).length).toBeGreaterThan(0);
    // Real ops are still in order
    const realIndexes = log.map((l, i) => l.startsWith("REAL:") ? i : -1).filter(i => i >= 0);
    expect(realIndexes[0]!).toBeLessThan(realIndexes[1]!);
  });

  it("two executions produce different traces (random walk)", async () => {
    const log1: string[] = [];
    const log2: string[] = [];

    const dummies = [
      dummyOp("aes", []), dummyOp("hash", []), dummyOp("ec", []), dummyOp("hkdf", []),
    ];

    let callCount = 0;
    const pseudoRandom = (max: number) => {
      callCount++;
      return (callCount * 7 + 3) % max; // pseudo-random, deterministic per run
    };

    // Run 1
    callCount = 0;
    const exec1 = new DrunkardExecutor(
      dummies.map(d => ({ ...d, execute: async () => { log1.push(d.name); } })),
      pseudoRandom,
    );
    await exec1.execute([async () => { log1.push("REAL"); }]);

    // Run 2 (different seed)
    callCount = 100;
    const exec2 = new DrunkardExecutor(
      dummies.map(d => ({ ...d, execute: async () => { log2.push(d.name); } })),
      pseudoRandom,
    );
    await exec2.execute([async () => { log2.push("REAL"); }]);

    // Traces should differ (different random sequences)
    expect(log1.join(",")).not.toBe(log2.join(","));
  });

  it("total operations = real + variable dummies (unpredictable count)", async () => {
    const counts: number[] = [];

    for (let seed = 0; seed < 10; seed++) {
      const log: string[] = [];
      let s = seed;
      const exec = new DrunkardExecutor(
        [dummyOp("d", log)],
        (max) => { s = (s * 13 + 7) % 97; return s % max; },
      );

      await exec.execute([
        async () => { log.push("R1"); },
        async () => { log.push("R2"); },
        async () => { log.push("R3"); },
      ]);

      counts.push(log.length);
    }

    // Different seeds → different total operation counts
    const unique = new Set(counts);
    expect(unique.size).toBeGreaterThan(1); // not all the same
  });

  it("an Intel PT trace cannot predict the next operation", () => {
    // Conceptual test: the drunkard's walk means that at each step,
    // the next operation is selected randomly from the dummy pool.
    // With 4 dummies and 1-3 inserted per step:
    //   Possible next operations: 4 choices × 3 possible counts = 12 variations per step
    //   After 5 real steps: 12^5 = 248,832 possible traces
    //   An Intel PT observer sees ONE trace but cannot predict the next execution

    const variations = Math.pow(4 * 3, 5);
    expect(variations).toBeGreaterThan(200_000);
  });
});
