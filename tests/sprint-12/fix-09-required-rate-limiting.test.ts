// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  createServer,
  createDevelopmentServer,
} from "../../src/api-gateway/server.js";
import { createTestDeps } from "../api-gateway/test-helpers.js";

describe("FIX 9 — Rate Limiting Required by Default", () => {
  it("createServer without rateLimiting config throws", () => {
    const deps = createTestDeps();
    expect(() => createServer(deps, { serviceAudience: "test" })).toThrow(
      "Rate limiting configuration is required",
    );
  });

  it("createServer without any options throws", () => {
    const deps = createTestDeps();
    expect(() => createServer(deps)).toThrow(
      "Rate limiting configuration is required",
    );
  });

  it("createServer with rateLimiting config succeeds", () => {
    const deps = createTestDeps();
    const app = createServer(deps, {
      serviceAudience: "test",
      rateLimiting: {
        trustedProxies: [],
      },
    });
    expect(app).toBeDefined();
  });

  it("createDevelopmentServer works without explicit rate limiting config", () => {
    const deps = createTestDeps();
    const app = createDevelopmentServer(deps);
    expect(app).toBeDefined();
  });

  it("createDevelopmentServer applies permissive defaults", async () => {
    const deps = createTestDeps();
    const app = createDevelopmentServer(deps);

    // Should respond to requests (server is working)
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });
    expect(response.statusCode).toBe(200);

    await app.close();
  });
});
