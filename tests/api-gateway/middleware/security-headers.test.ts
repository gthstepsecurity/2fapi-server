// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp } from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Security Headers Middleware", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  it("includes Strict-Transport-Security header", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.headers["strict-transport-security"]).toBe(
      "max-age=63072000; includeSubDomains",
    );
  });

  it("includes X-Content-Type-Options: nosniff", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("includes X-Frame-Options: DENY", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.headers["x-frame-options"]).toBe("DENY");
  });

  it("includes Cache-Control: no-store", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("does not expose Server header", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.headers["server"]).toBeUndefined();
  });

  it("security headers are present on error responses", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/nonexistent",
    });

    expect(response.headers["strict-transport-security"]).toBe(
      "max-age=63072000; includeSubDomains",
    );
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["cache-control"]).toBe("no-store");
  });
});
