// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp } from "../api-gateway/test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("I-05: X-Request-Id reflected without validation", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  it("ignores oversized X-Request-Id (>128 chars) and generates UUID", async () => {
    const oversizedId = "a".repeat(129);
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { "x-request-id": oversizedId },
    });

    const requestId = response.headers["x-request-id"] as string;
    expect(requestId).not.toBe(oversizedId);
    // Should be a UUID
    expect(requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("ignores X-Request-Id with special characters and generates UUID", async () => {
    const maliciousId = '<script>alert("xss")</script>';
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { "x-request-id": maliciousId },
    });

    const requestId = response.headers["x-request-id"] as string;
    expect(requestId).not.toBe(maliciousId);
    expect(requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("accepts valid alphanumeric X-Request-Id with hyphens", async () => {
    const validId = "abc-123-def-456";
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { "x-request-id": validId },
    });

    expect(response.headers["x-request-id"]).toBe(validId);
  });

  it("accepts valid UUID as X-Request-Id", async () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { "x-request-id": uuid },
    });

    expect(response.headers["x-request-id"]).toBe(uuid);
  });

  it("accepts X-Request-Id at exactly 128 characters", async () => {
    const maxId = "a".repeat(128);
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { "x-request-id": maxId },
    });

    expect(response.headers["x-request-id"]).toBe(maxId);
  });
});
