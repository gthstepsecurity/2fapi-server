// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp } from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Content-Type Enforcement Middleware", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  it("returns 415 when POST has wrong Content-Type", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "text/xml" },
      payload: "<data/>",
    });

    expect(response.statusCode).toBe(415);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:unsupported-media-type");
    expect(body.title).toBe("Unsupported Media Type");
    expect(body.detail).toBe("Content-Type must be application/json");
  });

  it("returns 415 when POST has no Content-Type", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "" },
      payload: "{}",
    });

    // Fastify rejects missing/empty content-type on POST
    expect(response.statusCode).toBe(415);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:unsupported-media-type");
  });

  it("accepts application/json content type on POST", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({
        clientIdentifier: "test",
        commitment: Buffer.from(new Uint8Array(32).fill(1)).toString("base64"),
        proofOfPossession: Buffer.from(new Uint8Array(96).fill(1)).toString("base64"),
      }),
    });

    // Should not be 415
    expect(response.statusCode).not.toBe(415);
  });

  it("does not enforce Content-Type on GET requests", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.statusCode).toBe(200);
  });
});
