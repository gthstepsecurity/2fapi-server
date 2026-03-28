// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Verifies that ALL /v1/ API responses have uniform byte size.
 *
 * An observer measuring TLS record lengths MUST NOT be able to determine:
 *   - Which endpoint was called
 *   - Whether the request succeeded or failed
 *   - What type of error occurred
 *
 * Every JSON response on /v1/ is padded to 1024 bytes by the global
 * response-padding-hook middleware.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  validBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Response Padding Hook — uniform TLS record size", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
  });

  afterEach(async () => {
    await app.close();
  });

  async function measureBodySize(
    method: "GET" | "POST",
    url: string,
    payload?: Record<string, unknown>,
  ): Promise<{ status: number; size: number }> {
    const response = await app.inject({
      method,
      url,
      headers: { "content-type": "application/json" },
      payload,
    });
    return {
      status: response.statusCode,
      size: Buffer.byteLength(response.body, "utf-8"),
    };
  }

  // --- Core assertion: all /v1/ routes produce same-size bodies ---

  it("all /v1/ JSON responses have identical byte size (1024)", async () => {
    const responses = await Promise.all([
      // Enrollment — 400 (missing fields)
      measureBodySize("POST", "/v1/enroll", {}),

      // Enrollment — valid payload → 201 or 409
      measureBodySize("POST", "/v1/enroll", {
        clientIdentifier: "test-client",
        commitment: validBase64(),
        proofOfPossession: validBase64(96),
      }),

      // Challenge — 400 (missing fields)
      measureBodySize("POST", "/v1/challenge", {}),

      // Challenge — valid
      measureBodySize("POST", "/v1/challenge", {
        clientIdentifier: "alice",
      }),

      // Verify — 400 (missing fields)
      measureBodySize("POST", "/v1/verify", {}),

      // Verify — success
      measureBodySize("POST", "/v1/verify", {
        clientIdentifier: "alice-payment-service",
        challengeId: "ch-42",
        proof: validBase64(),
        channelBinding: validBase64(),
        domainSeparationTag: "2FApi-v1.0-Sigma",
      }),

      // Resource — 401 (no token)
      measureBodySize("GET", "/v1/resources/test-resource"),
    ]);

    const sizes = responses.map((r) => r.size);
    const uniqueSizes = new Set(sizes);

    // ALL responses must be the SAME size
    expect(
      uniqueSizes.size,
      `Expected 1 unique size, got ${uniqueSizes.size}: ${[...uniqueSizes].join(", ")} bytes. ` +
      `Responses: ${responses.map((r, i) => `[${i}] ${r.status}=${r.size}b`).join(", ")}`,
    ).toBe(1);

    // And that size should be 1024
    expect(sizes[0]).toBe(1024);
  });

  it("padding contains random data (not compressible, anti-CRIME/BREACH)", async () => {
    const r1 = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice",
        challengeId: "ch-42",
        proof: validBase64(),
        channelBinding: validBase64(),
        domainSeparationTag: "2FApi-v1.0-Sigma",
      },
    });

    const r2 = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice",
        challengeId: "ch-42",
        proof: validBase64(),
        channelBinding: validBase64(),
        domainSeparationTag: "2FApi-v1.0-Sigma",
      },
    });

    const b1 = JSON.parse(r1.body);
    const b2 = JSON.parse(r2.body);

    // Both padded to same size
    expect(r1.body.length).toBe(r2.body.length);

    // Padding is random — different between requests
    expect(b1._p).toBeDefined();
    expect(b2._p).toBeDefined();
    expect(b1._p).not.toBe(b2._p);
  });

  it("/health is NOT padded (public, non-sensitive)", async () => {
    const r = await app.inject({ method: "GET", url: "/health" });
    expect(r.body.length).toBeLessThan(100);
    expect(JSON.parse(r.body)._p).toBeUndefined();
  });
});
