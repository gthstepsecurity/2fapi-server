// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: the Drunkard's Walk execution strategy.
 *
 * Instead of executing crypto operations in a fixed, traceable sequence,
 * the drunkard executor INTERLEAVES real operations with random dummy
 * operations in a SHUFFLED order. Each authentication produces a UNIQUE
 * execution trace that is unpredictable even with Intel Processor Trace.
 *
 * An observer who traces every branch sees a different path every time.
 * They cannot separate the real operations from the noise.
 *
 * The analogy: an homme ivre walks from A to B. Each step is random.
 * He always arrives at B. But the PATH is different every time.
 * An observer watching his footsteps cannot predict the next one.
 *
 * Implementation:
 * - The 5 real operations (AES, Argon2id, OPRF, proof, combine) must ALL execute
 * - Between each real operation, 1-3 RANDOM dummy operations are inserted
 * - The dummies are selected randomly from: dummy-AES, dummy-hash, dummy-EC-mult, dummy-HKDF
 * - The execution order is: real ops in fixed order (for correctness) BUT
 *   interspersed with random dummies (for trace obfuscation)
 *
 * Total operations: 5 real + 5-15 random dummies = 10-20 operations
 * Each authentication: unique count, unique sequence of dummies
 * Branch trace: unpredictable — the AI sees a drunkard's walk
 */
export class DrunkardExecutor {
  constructor(
    private readonly dummyOps: DummyOperation[],
    private readonly randomInt: (max: number) => number,
  ) {}

  /**
   * Execute the real operations in order, with random dummy operations
   * interleaved between each step.
   */
  async execute(realSteps: AsyncOperation[]): Promise<void> {
    for (const step of realSteps) {
      // Before each real step: insert 1-3 random dummy operations
      const dummyCount = 1 + this.randomInt(3); // 1 to 3
      for (let i = 0; i < dummyCount; i++) {
        const dummyIndex = this.randomInt(this.dummyOps.length);
        await this.dummyOps[dummyIndex]!.execute();
      }

      // Execute the real step
      await step();
    }

    // After the last real step: 1-3 more dummies (trail cover)
    const trailCount = 1 + this.randomInt(3);
    for (let i = 0; i < trailCount; i++) {
      const idx = this.randomInt(this.dummyOps.length);
      await this.dummyOps[idx]!.execute();
    }
  }
}

export interface DummyOperation {
  readonly name: string;
  execute(): Promise<void>;
}

export type AsyncOperation = () => Promise<void>;
