// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { StubClientSuspender } from "../../../../../src/security-monitoring/infrastructure/adapter/outgoing/stub-client-suspender.js";

describe("StubClientSuspender", () => {
  it("records suspension calls", async () => {
    const stub = new StubClientSuspender();
    const result = await stub.suspend("alice", "concurrent_session");

    expect(result).toBe(true);
    expect(stub.suspensions).toHaveLength(1);
    expect(stub.suspensions[0]).toEqual({
      clientIdentifier: "alice",
      reason: "concurrent_session",
    });
  });

  it("can be configured to return false (already suspended)", async () => {
    const stub = new StubClientSuspender();
    stub.setAlreadySuspended(true);

    const result = await stub.suspend("alice", "manual");
    expect(result).toBe(false);
  });

  it("records multiple suspension calls", async () => {
    const stub = new StubClientSuspender();
    await stub.suspend("alice", "concurrent_session");
    await stub.suspend("bob", "volume_anomaly");

    expect(stub.suspensions).toHaveLength(2);
  });
});
