// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp } from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Health & OpenAPI Routes", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  describe("GET /health", () => {
    it("returns 200 with status ok", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe("ok");
      expect(body.version).toBe("1.0");
    });

    it("includes X-Request-Id header", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      expect(response.headers["x-request-id"]).toBeDefined();
    });

    it("does not require authentication", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      expect(response.statusCode).toBe(200);
    });
  });

  describe("GET /v1/openapi.json", () => {
    it("returns 200 with OpenAPI spec", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/openapi.json",
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.openapi).toBe("3.1.0");
      expect(body.info.title).toContain("2FApi");
      expect(body.paths).toBeDefined();
    });

    it("returns application/json content type", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/openapi.json",
      });

      expect(response.headers["content-type"]).toContain("application/json");
    });
  });
});
