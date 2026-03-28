// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, vi } from "vitest";
import { NapiRotationProofVerifier } from "../../src/client-registration/infrastructure/adapter/outgoing/napi-rotation-proof-verifier.js";

/**
 * Sprint 17 — Finding 3 (MEDIUM): Rotation Proof Short-Circuit Timing Leak
 *
 * The `return currentValid && newValid` expression short-circuits:
 * if currentValid is false, newValid is never evaluated.
 * This leaks which proof failed through timing differences.
 *
 * Fix: Both proofs must ALWAYS be verified, regardless of the first result.
 */

function createMockCommitment(bytes: Uint8Array) {
  return { toBytes: () => bytes };
}

describe("Rotation Proof Constant-Time Verification", () => {
  it("should execute both proof verifications when first proof is invalid", () => {
    let currentVerifyCalled = false;
    let newVerifyCalled = false;

    const mockModule = {
      hashTranscript: (_data: Buffer) => Buffer.alloc(32, 0x01),
      verifyProofEquation: (params: { commitment: Buffer }) => {
        // Use commitment content to distinguish which verification is called
        const commitmentBytes = new Uint8Array(params.commitment);
        if (commitmentBytes[0] === 0xaa) {
          currentVerifyCalled = true;
          return false; // Current proof is INVALID
        }
        if (commitmentBytes[0] === 0xbb) {
          newVerifyCalled = true;
          return true; // New proof is VALID
        }
        return false;
      },
    };

    const verifier = new NapiRotationProofVerifier(
      mockModule,
      Buffer.alloc(32, 0x01),
      Buffer.alloc(32, 0x02),
    );

    const currentCommitment = createMockCommitment(new Uint8Array(32).fill(0xaa));
    const newCommitment = createMockCommitment(new Uint8Array(32).fill(0xbb));
    const proof96 = new Uint8Array(96);

    const result = verifier.verify(
      currentCommitment as any,
      proof96,
      newCommitment as any,
      proof96,
    );

    expect(result).toBe(false);
    // CRITICAL: Both verifications MUST have been called
    expect(currentVerifyCalled).toBe(true);
    expect(newVerifyCalled).toBe(true);
  });

  it("should execute both proof verifications when second proof is invalid", () => {
    let currentVerifyCalled = false;
    let newVerifyCalled = false;

    const mockModule = {
      hashTranscript: (_data: Buffer) => Buffer.alloc(32, 0x01),
      verifyProofEquation: (params: { commitment: Buffer }) => {
        const commitmentBytes = new Uint8Array(params.commitment);
        if (commitmentBytes[0] === 0xcc) {
          currentVerifyCalled = true;
          return true; // Current proof is VALID
        }
        if (commitmentBytes[0] === 0xdd) {
          newVerifyCalled = true;
          return false; // New proof is INVALID
        }
        return false;
      },
    };

    const verifier = new NapiRotationProofVerifier(
      mockModule,
      Buffer.alloc(32, 0x01),
      Buffer.alloc(32, 0x02),
    );

    const currentCommitment = createMockCommitment(new Uint8Array(32).fill(0xcc));
    const newCommitment = createMockCommitment(new Uint8Array(32).fill(0xdd));
    const proof96 = new Uint8Array(96);

    const result = verifier.verify(
      currentCommitment as any,
      proof96,
      newCommitment as any,
      proof96,
    );

    expect(result).toBe(false);
    expect(currentVerifyCalled).toBe(true);
    expect(newVerifyCalled).toBe(true);
  });

  it("should return true only when both proofs are valid", () => {
    const mockModule = {
      hashTranscript: (_data: Buffer) => Buffer.alloc(32, 0x01),
      verifyProofEquation: () => true,
    };

    const verifier = new NapiRotationProofVerifier(
      mockModule,
      Buffer.alloc(32, 0x01),
      Buffer.alloc(32, 0x02),
    );

    const commitment = createMockCommitment(new Uint8Array(32).fill(0xee));
    const proof96 = new Uint8Array(96);

    const result = verifier.verify(
      commitment as any,
      proof96,
      commitment as any,
      proof96,
    );

    expect(result).toBe(true);
  });

  it("source code should not use && for combining proof results", () => {
    const fs = require("node:fs");
    const source = fs.readFileSync(
      require("node:path").resolve(
        __dirname,
        "../../src/client-registration/infrastructure/adapter/outgoing/napi-rotation-proof-verifier.ts",
      ),
      "utf-8",
    );
    // The line "return currentValid && newValid" should be gone
    expect(source).not.toMatch(/return\s+currentValid\s*&&\s*newValid/);
  });
});
