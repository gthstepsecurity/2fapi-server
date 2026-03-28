// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const VALID_WORD_COUNTS = [12, 18, 24] as const;
type ValidWordCount = (typeof VALID_WORD_COUNTS)[number];

export type RecoveryMode = "phrase_only" | "external_only" | "phrase_and_external";

export interface RecoveryConfigOverrides {
  readonly wordCount?: number;
  readonly argon2Memory?: number;
  readonly argon2Iterations?: number;
  readonly argon2Parallelism?: number;
  readonly maxRecoveryAttempts?: number;
  readonly recoveryMode?: RecoveryMode;
}

/**
 * Value Object representing recovery configuration for a client operator.
 * Immutable (frozen after construction).
 */
export class RecoveryConfig {
  readonly wordCount: ValidWordCount;
  readonly argon2Memory: number;
  readonly argon2Iterations: number;
  readonly argon2Parallelism: number;
  readonly maxRecoveryAttempts: number;
  readonly recoveryMode: RecoveryMode;

  private constructor(
    wordCount: ValidWordCount,
    argon2Memory: number,
    argon2Iterations: number,
    argon2Parallelism: number,
    maxRecoveryAttempts: number,
    recoveryMode: RecoveryMode,
  ) {
    this.wordCount = wordCount;
    this.argon2Memory = argon2Memory;
    this.argon2Iterations = argon2Iterations;
    this.argon2Parallelism = argon2Parallelism;
    this.maxRecoveryAttempts = maxRecoveryAttempts;
    this.recoveryMode = recoveryMode;
    Object.freeze(this);
  }

  /** Creates a RecoveryConfig with all default values */
  static defaults(): RecoveryConfig {
    return new RecoveryConfig(12, 65536, 3, 4, 3, "phrase_and_external");
  }

  /**
   * Creates a RecoveryConfig by merging overrides onto defaults.
   * @throws if any override value is invalid
   */
  static create(overrides: RecoveryConfigOverrides): RecoveryConfig {
    const wordCount = (overrides.wordCount ?? 12) as ValidWordCount;
    if (!VALID_WORD_COUNTS.includes(wordCount)) {
      throw new Error("Word count must be 12, 18, or 24");
    }

    const argon2Memory = overrides.argon2Memory ?? 65536;
    if (argon2Memory <= 0) {
      throw new Error("Argon2 memory must be a positive integer");
    }

    const argon2Iterations = overrides.argon2Iterations ?? 3;
    if (argon2Iterations <= 0) {
      throw new Error("Argon2 iterations must be a positive integer");
    }

    const argon2Parallelism = overrides.argon2Parallelism ?? 4;
    if (argon2Parallelism <= 0) {
      throw new Error("Argon2 parallelism must be a positive integer");
    }

    const maxRecoveryAttempts = overrides.maxRecoveryAttempts ?? 3;
    if (maxRecoveryAttempts <= 0) {
      throw new Error("Max recovery attempts must be a positive integer");
    }

    const recoveryMode = overrides.recoveryMode ?? "phrase_and_external";

    return new RecoveryConfig(
      wordCount,
      argon2Memory,
      argon2Iterations,
      argon2Parallelism,
      maxRecoveryAttempts,
      recoveryMode,
    );
  }
}
