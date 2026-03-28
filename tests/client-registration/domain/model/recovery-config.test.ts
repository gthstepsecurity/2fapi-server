// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RecoveryConfig } from "../../../../src/client-registration/domain/model/recovery-config.js";

describe("RecoveryConfig", () => {
  describe("defaults", () => {
    it("creates a config with default values", () => {
      const config = RecoveryConfig.defaults();
      expect(config.wordCount).toBe(12);
      expect(config.argon2Memory).toBe(65536);
      expect(config.argon2Iterations).toBe(3);
      expect(config.argon2Parallelism).toBe(4);
      expect(config.maxRecoveryAttempts).toBe(3);
      expect(config.recoveryMode).toBe("phrase_and_external");
    });
  });

  describe("create", () => {
    it("creates a config with overrides merged onto defaults", () => {
      const config = RecoveryConfig.create({ wordCount: 24 });
      expect(config.wordCount).toBe(24);
      // Other values remain at defaults
      expect(config.argon2Memory).toBe(65536);
      expect(config.argon2Iterations).toBe(3);
      expect(config.argon2Parallelism).toBe(4);
      expect(config.maxRecoveryAttempts).toBe(3);
      expect(config.recoveryMode).toBe("phrase_and_external");
    });

    it("overrides argon2Memory", () => {
      const config = RecoveryConfig.create({ argon2Memory: 131072 });
      expect(config.argon2Memory).toBe(131072);
    });

    it("overrides argon2Iterations", () => {
      const config = RecoveryConfig.create({ argon2Iterations: 5 });
      expect(config.argon2Iterations).toBe(5);
    });

    it("overrides argon2Parallelism", () => {
      const config = RecoveryConfig.create({ argon2Parallelism: 8 });
      expect(config.argon2Parallelism).toBe(8);
    });

    it("overrides maxRecoveryAttempts", () => {
      const config = RecoveryConfig.create({ maxRecoveryAttempts: 5 });
      expect(config.maxRecoveryAttempts).toBe(5);
    });

    it("overrides recoveryMode to phrase_only", () => {
      const config = RecoveryConfig.create({ recoveryMode: "phrase_only" });
      expect(config.recoveryMode).toBe("phrase_only");
    });

    it("overrides recoveryMode to external_only", () => {
      const config = RecoveryConfig.create({ recoveryMode: "external_only" });
      expect(config.recoveryMode).toBe("external_only");
    });

    it("overrides multiple values at once", () => {
      const config = RecoveryConfig.create({
        wordCount: 18,
        argon2Memory: 32768,
        argon2Iterations: 2,
        argon2Parallelism: 2,
        maxRecoveryAttempts: 5,
        recoveryMode: "phrase_only",
      });
      expect(config.wordCount).toBe(18);
      expect(config.argon2Memory).toBe(32768);
      expect(config.argon2Iterations).toBe(2);
      expect(config.argon2Parallelism).toBe(2);
      expect(config.maxRecoveryAttempts).toBe(5);
      expect(config.recoveryMode).toBe("phrase_only");
    });

    it("rejects invalid word count (not 12, 18, or 24)", () => {
      expect(() => RecoveryConfig.create({ wordCount: 15 })).toThrow(
        "Word count must be 12, 18, or 24",
      );
    });

    it("rejects word count of 0", () => {
      expect(() => RecoveryConfig.create({ wordCount: 0 as 12 })).toThrow(
        "Word count must be 12, 18, or 24",
      );
    });

    it("rejects argon2Memory less than or equal to 0", () => {
      expect(() => RecoveryConfig.create({ argon2Memory: 0 })).toThrow(
        "Argon2 memory must be a positive integer",
      );
    });

    it("rejects argon2Memory that is negative", () => {
      expect(() => RecoveryConfig.create({ argon2Memory: -1 })).toThrow(
        "Argon2 memory must be a positive integer",
      );
    });

    it("rejects argon2Iterations less than or equal to 0", () => {
      expect(() => RecoveryConfig.create({ argon2Iterations: 0 })).toThrow(
        "Argon2 iterations must be a positive integer",
      );
    });

    it("rejects argon2Parallelism less than or equal to 0", () => {
      expect(() => RecoveryConfig.create({ argon2Parallelism: 0 })).toThrow(
        "Argon2 parallelism must be a positive integer",
      );
    });

    it("rejects maxRecoveryAttempts less than or equal to 0", () => {
      expect(() => RecoveryConfig.create({ maxRecoveryAttempts: 0 })).toThrow(
        "Max recovery attempts must be a positive integer",
      );
    });
  });

  describe("immutability", () => {
    it("is a frozen object (no property mutation)", () => {
      const config = RecoveryConfig.defaults();
      expect(Object.isFrozen(config)).toBe(true);
    });

    it("created config is also frozen", () => {
      const config = RecoveryConfig.create({ wordCount: 24 });
      expect(Object.isFrozen(config)).toBe(true);
    });
  });
});
