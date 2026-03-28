// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { CheckSuspensionStatusUseCase } from "../../../../src/security-monitoring/application/usecase/check-suspension-status.usecase.js";

// Minimal port for client status lookup
interface ClientStatusLookup {
  getStatus(clientIdentifier: string): Promise<"active" | "suspended" | "revoked" | null>;
}

class StubClientStatusLookup implements ClientStatusLookup {
  private statuses = new Map<string, "active" | "suspended" | "revoked">();

  async getStatus(clientIdentifier: string): Promise<"active" | "suspended" | "revoked" | null> {
    return this.statuses.get(clientIdentifier) ?? null;
  }

  setStatus(clientIdentifier: string, status: "active" | "suspended" | "revoked"): void {
    this.statuses.set(clientIdentifier, status);
  }
}

describe("CheckSuspensionStatusUseCase", () => {
  let useCase: CheckSuspensionStatusUseCase;
  let clientStatusLookup: StubClientStatusLookup;

  beforeEach(() => {
    clientStatusLookup = new StubClientStatusLookup();
    useCase = new CheckSuspensionStatusUseCase(clientStatusLookup);
  });

  it("returns active for an active client", async () => {
    clientStatusLookup.setStatus("alice", "active");

    const result = await useCase.execute({ clientIdentifier: "alice" });

    expect(result.status).toBe("active");
  });

  it("returns suspended for a suspended client", async () => {
    clientStatusLookup.setStatus("alice", "suspended");

    const result = await useCase.execute({ clientIdentifier: "alice" });

    expect(result.status).toBe("suspended");
  });

  it("returns active for an unknown client (no info leak)", async () => {
    const result = await useCase.execute({ clientIdentifier: "unknown" });

    expect(result.status).toBe("active");
  });

  it("returns active for a revoked client (suspension check only)", async () => {
    clientStatusLookup.setStatus("alice", "revoked");

    const result = await useCase.execute({ clientIdentifier: "alice" });

    // This port only answers active/suspended; revoked maps to "active" here
    // because the CheckSuspensionStatus port is specifically for suspension
    expect(result.status).toBe("active");
  });
});
