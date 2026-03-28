// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubValidateToken,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Resource Route — GET /v1/resources/:resourceId", () => {
  let app: FastifyInstance;
  let validateToken: StubValidateToken;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    validateToken = result.deps.validateToken;
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Happy Path ---

  it("returns 200 with resource data when token is valid", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
      headers: {
        authorization: "Bearer valid-token-abc",
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.resourceId).toBe("payment-config");
    expect(body.clientIdentifier).toBe("test-client");
  });

  it("passes token to validation use case with configured serviceAudience", async () => {
    await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
      headers: {
        authorization: "Bearer my-token-123",
      },
    });

    expect(validateToken.lastRequest).not.toBeNull();
    expect(validateToken.lastRequest!.bearerToken).toBe("my-token-123");
    expect(validateToken.lastRequest!.expectedAudience).toBe("test-service");
  });

  it("Bearer scheme is case-insensitive", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
      headers: {
        authorization: "bearer valid-token-abc",
      },
    });

    expect(response.statusCode).toBe(200);
  });

  // --- Error Cases ---

  it("returns 401 without Authorization header", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers["www-authenticate"]).toBe('Bearer realm="2fapi"');
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:unauthorized");
    expect(body.detail).toBe("Bearer token required");
  });

  it("returns 401 with non-Bearer scheme", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
      headers: {
        authorization: "Basic abc123",
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers["www-authenticate"]).toBe('Bearer realm="2fapi"');
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("Bearer required");
  });

  it("returns 401 when token validation fails", async () => {
    validateToken.setResponse({
      success: false,
      error: "access_denied",
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
      headers: {
        authorization: "Bearer invalid-token",
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers["www-authenticate"]).toContain("invalid_token");
  });

  it("includes X-Request-Id header", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/resources/payment-config",
      headers: {
        authorization: "Bearer valid-token",
        "x-request-id": "res-req-1",
      },
    });

    expect(response.headers["x-request-id"]).toBe("res-req-1");
  });
});
