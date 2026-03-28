// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import type {
  ReactivateViaExternal,
  ReactivateViaExternalRequest,
  ReactivateViaExternalResponse,
} from "../../../../../src/client-registration/domain/port/incoming/reactivate-via-external.js";

describe("ReactivateViaExternal port", () => {
  it("defines execute method with request and response types", async () => {
    const request: ReactivateViaExternalRequest = {
      clientIdentifier: "alice-payment-service",
      adminIdentity: "bob-admin-id",
      newCommitmentBytes: new Uint8Array(32).fill(0xbb),
      newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
    };

    const port: ReactivateViaExternal = {
      execute: async (_req: ReactivateViaExternalRequest): Promise<ReactivateViaExternalResponse> => {
        return { success: true };
      },
    };

    const result = await port.execute(request);
    expect(result).toEqual({ success: true });
  });

  it("success response has success true", async () => {
    const port: ReactivateViaExternal = {
      execute: async () => ({ success: true }),
    };

    const result = await port.execute({
      clientIdentifier: "alice-payment-service",
      adminIdentity: "bob-admin-id",
      newCommitmentBytes: new Uint8Array(32).fill(0xbb),
      newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
    });

    expect(result.success).toBe(true);
  });

  it("failure response has success false and generic error", async () => {
    const port: ReactivateViaExternal = {
      execute: async () => ({ success: false, error: "reactivation_failed" as const }),
    };

    const result = await port.execute({
      clientIdentifier: "alice-payment-service",
      adminIdentity: "",
      newCommitmentBytes: new Uint8Array(32).fill(0xbb),
      newCommitmentProofBytes: new Uint8Array(96).fill(0xcc),
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("reactivation_failed");
    }
  });
});
