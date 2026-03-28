// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp } from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Request ID Middleware", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  it("generates a UUID X-Request-Id when client does not provide one", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    const requestId = response.headers["x-request-id"] as string;
    expect(requestId).toBeDefined();
    expect(requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("echoes client-provided X-Request-Id", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { "x-request-id": "abc-123-def" },
    });

    expect(response.headers["x-request-id"]).toBe("abc-123-def");
  });

  it("includes X-Request-Id on error responses too", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/nonexistent",
      headers: { "x-request-id": "err-req-1" },
    });

    expect(response.headers["x-request-id"]).toBe("err-req-1");
  });
});
