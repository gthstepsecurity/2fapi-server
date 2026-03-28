// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp, validBase64 } from "../api-gateway/test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("L-11: Consistent clientIdentifier validation across all routes", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    ({ app } = createTestApp());
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Revocation Route ---

  it("revocation rejects clientId with special characters", async () => {
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/alice%20%3B%20DROP%20TABLE",
      headers: { "x-admin-identity": "CN=admin,O=2fapi" },
    });

    expect(response.statusCode).toBe(400);
  });

  it("revocation rejects empty clientId", async () => {
    // Fastify won't match an empty param in /:clientId, so we test with a space
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/%20",
      headers: { "x-admin-identity": "CN=admin,O=2fapi" },
    });

    expect(response.statusCode).toBe(400);
  });

  it("revocation rejects clientId over 100 characters (Fastify maxParamLength default)", async () => {
    const longId = "a".repeat(101);
    const response = await app.inject({
      method: "DELETE",
      url: `/v1/clients/${longId}`,
      headers: { "x-admin-identity": "CN=admin,O=2fapi" },
    });

    // Fastify rejects params > 100 chars with 404 before our handler runs
    expect(response.statusCode).toBe(404);
  });

  it("revocation accepts valid clientId", async () => {
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/alice-payment-service",
      headers: { "x-admin-identity": "CN=admin,O=2fapi" },
    });

    // Should NOT be 400 — either 204 (success) or 403 etc. but not validation error
    expect(response.statusCode).not.toBe(400);
  });

  // --- Rotation Route ---

  it("rotation rejects clientId with special characters", async () => {
    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice%3B%20DROP/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: {
        currentProof: validBase64(),
        newCommitment: validBase64(),
        newCommitmentProof: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("rotation rejects clientId over 100 characters (Fastify maxParamLength default)", async () => {
    const longId = "b".repeat(101);
    const response = await app.inject({
      method: "PUT",
      url: `/v1/clients/${longId}/commitment`,
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: {
        currentProof: validBase64(),
        newCommitment: validBase64(),
        newCommitmentProof: validBase64(),
      },
    });

    // Fastify rejects params > 100 chars with 404 before our handler runs
    expect(response.statusCode).toBe(404);
  });

  // --- Challenge Route ---

  it("challenge rejects clientIdentifier with special characters in body", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice; DROP TABLE",
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("challenge rejects clientIdentifier over 128 characters in body", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "c".repeat(129),
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  // --- Verification Route ---

  it("verification rejects clientIdentifier with special characters in body", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice; DROP TABLE",
        challengeId: "ch-42",
        proof: validBase64(),
        channelBinding: validBase64(),
        domainSeparationTag: "2FApi-v1.0-Sigma",
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("verification rejects clientIdentifier over 128 characters in body", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "d".repeat(129),
        challengeId: "ch-42",
        proof: validBase64(),
        channelBinding: validBase64(),
        domainSeparationTag: "2FApi-v1.0-Sigma",
      },
    });

    expect(response.statusCode).toBe(400);
  });
});
