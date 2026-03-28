// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp } from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Error Handler Middleware", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  it("returns RFC 7807 Problem Details for malformed JSON", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: "not-json{{",
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:malformed-body");
    expect(body.title).toBe("Bad Request");
    expect(body.detail).toBe("Request body is not valid JSON");
    expect(body.status).toBe(400);
    expect(body.instance).toBeDefined();
  });

  it("returns 404 Problem Details for unknown routes", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/nonexistent",
    });

    expect(response.statusCode).toBe(404);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:not-found");
    expect(body.title).toBe("Not Found");
    expect(body.status).toBe(404);
  });

  it("returns migration hint for unversioned paths", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/clients",
      headers: { "content-type": "application/json" },
      payload: "{}",
    });

    expect(response.statusCode).toBe(404);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("/v1/clients");
  });

  it("includes instance field matching X-Request-Id", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: {
        "content-type": "application/json",
        "x-request-id": "req-abc-456",
      },
      payload: "not-json{{",
    });

    const body = JSON.parse(response.body);
    expect(body.instance).toBe("req-abc-456");
    expect(response.headers["x-request-id"]).toBe("req-abc-456");
  });

  it("error responses have application/problem+json content type", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/nonexistent",
    });

    expect(response.headers["content-type"]).toContain(
      "application/problem+json",
    );
  });
});
