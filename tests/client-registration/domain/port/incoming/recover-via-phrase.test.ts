// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import type {
  RecoverViaPhrase,
  RecoverViaPhraseRequest,
  RecoverViaPhraseResponse,
} from "../../../../../src/client-registration/domain/port/incoming/recover-via-phrase.js";

describe("RecoverViaPhrase port", () => {
  it("defines execute method with request and response types", async () => {
    const request: RecoverViaPhraseRequest = {
      clientIdentifier: "alice-payment-service",
      words: [
        "abandon", "ability", "able", "about",
        "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident",
      ],
      newCommitmentBytes: new Uint8Array(32).fill(0xbb),
      newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
    };

    const port: RecoverViaPhrase = {
      execute: async (_req: RecoverViaPhraseRequest): Promise<RecoverViaPhraseResponse> => {
        return { success: true };
      },
    };

    const result = await port.execute(request);
    expect(result).toEqual({ success: true });
  });

  it("success response has success true", async () => {
    const port: RecoverViaPhrase = {
      execute: async () => ({ success: true }),
    };

    const result = await port.execute({
      clientIdentifier: "alice-payment-service",
      words: ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"],
      newCommitmentBytes: new Uint8Array(32).fill(0xbb),
      newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
    });

    expect(result.success).toBe(true);
  });

  it("failure response has success false and generic error", async () => {
    const port: RecoverViaPhrase = {
      execute: async () => ({ success: false, error: "recovery_failed" as const }),
    };

    const result = await port.execute({
      clientIdentifier: "alice-payment-service",
      words: ["wrong", "words", "here", "not", "valid", "at", "all", "but", "twelve", "total", "needed", "now"],
      newCommitmentBytes: new Uint8Array(32).fill(0xbb),
      newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("recovery_failed");
    }
  });
});
