// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";

/**
 * Integration tests for the full bootstrap process.
 *
 * Tests that the application can start with development configuration
 * (in-memory adapters) without external infrastructure.
 *
 * Run with:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 */
describe.skip("Bootstrap [integration]", () => {
  it("should bootstrap in development mode", async () => {
    // Set development environment
    const originalEnv = process.env["TWOFAPI_ENV"];
    process.env["TWOFAPI_ENV"] = "development";

    try {
      const { bootstrap } = await import(
        "../../src/config/bootstrap.js"
      );

      const app = await bootstrap();
      expect(app).toBeDefined();

      // Verify health endpoint works
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      expect(response.statusCode).toBe(200);
    } finally {
      if (originalEnv !== undefined) {
        process.env["TWOFAPI_ENV"] = originalEnv;
      } else {
        delete process.env["TWOFAPI_ENV"];
      }
    }
  });

  it("should detect environment from TWOFAPI_ENV", async () => {
    const { detectEnvironment } = await import(
      "../../src/config/environment.js"
    );

    const originalEnv = process.env["TWOFAPI_ENV"];

    try {
      process.env["TWOFAPI_ENV"] = "production";
      expect(detectEnvironment()).toBe("production");

      process.env["TWOFAPI_ENV"] = "test";
      expect(detectEnvironment()).toBe("test");

      process.env["TWOFAPI_ENV"] = "development";
      expect(detectEnvironment()).toBe("development");

      delete process.env["TWOFAPI_ENV"];
      delete process.env["NODE_ENV"];
      expect(detectEnvironment()).toBe("development");
    } finally {
      if (originalEnv !== undefined) {
        process.env["TWOFAPI_ENV"] = originalEnv;
      } else {
        delete process.env["TWOFAPI_ENV"];
      }
    }
  });
});
