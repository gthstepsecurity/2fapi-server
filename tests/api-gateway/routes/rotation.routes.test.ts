// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubRotateCommitment,
  StubValidateToken,
  validBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Rotation Route — PUT /v1/clients/:clientId/commitment", () => {
  let app: FastifyInstance;
  let rotateCommitment: StubRotateCommitment;
  let validateToken: StubValidateToken;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    rotateCommitment = result.deps.rotateCommitment;
    validateToken = result.deps.validateToken;
  });

  afterEach(async () => {
    await app.close();
  });

  function validRotationPayload() {
    return {
      currentProof: validBase64(),
      newCommitment: validBase64(),
      newCommitmentProof: validBase64(),
    };
  }

  // --- Happy Path ---

  it("returns 200 with rotatedAt on success", async () => {
    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: validRotationPayload(),
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.rotatedAt).toBeDefined();
    // rotatedAt should be ISO 8601
    expect(new Date(body.rotatedAt).toISOString()).toBe(body.rotatedAt);
  });

  it("passes decoded bytes to use case", async () => {
    await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: validRotationPayload(),
    });

    expect(rotateCommitment.lastRequest).not.toBeNull();
    expect(rotateCommitment.lastRequest!.clientIdentifier).toBe("alice-payment-service");
    expect(rotateCommitment.lastRequest!.currentProofBytes).toBeInstanceOf(Uint8Array);
    expect(rotateCommitment.lastRequest!.newCommitmentBytes).toBeInstanceOf(Uint8Array);
    expect(rotateCommitment.lastRequest!.newCommitmentProofBytes).toBeInstanceOf(Uint8Array);
  });

  // --- Auth Errors ---

  it("returns 401 without Authorization header", async () => {
    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: { "content-type": "application/json" },
      payload: validRotationPayload(),
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers["www-authenticate"]).toContain('Bearer realm="2fapi"');
  });

  it("validates token against configured serviceAudience", async () => {
    await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: validRotationPayload(),
    });

    expect(validateToken.lastRequest).not.toBeNull();
    expect(validateToken.lastRequest!.expectedAudience).toBe("test-service");
  });

  it("returns 401 when token validation fails", async () => {
    validateToken.setResponse({
      success: false,
      error: "access_denied",
    });

    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer invalid-token",
      },
      payload: validRotationPayload(),
    });

    expect(response.statusCode).toBe(401);
  });

  // --- Validation Errors ---

  it("returns 400 when currentProof is missing", async () => {
    const { currentProof, ...rest } = validRotationPayload();

    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("currentProof");
  });

  it("returns 400 when newCommitment is missing", async () => {
    const { newCommitment, ...rest } = validRotationPayload();

    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("newCommitment");
  });

  it("returns 400 when newCommitmentProof is missing", async () => {
    const { newCommitmentProof, ...rest } = validRotationPayload();

    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("newCommitmentProof");
  });

  it("returns 400 when newCommitment has invalid base64", async () => {
    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: {
        currentProof: validBase64(),
        newCommitment: "not-base64!!!",
        newCommitmentProof: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("base64");
    expect(body.detail).toContain("newCommitment");
  });

  // --- Domain Errors ---

  it("returns 401 when rotation is refused", async () => {
    rotateCommitment.setResponse({
      success: false,
      error: "rotation_failed",
    });

    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
      },
      payload: validRotationPayload(),
    });

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:rotation-refused");
    expect(body.detail).toBe("Rotation could not be completed");
  });

  it("includes X-Request-Id header", async () => {
    const response = await app.inject({
      method: "PUT",
      url: "/v1/clients/alice-payment-service/commitment",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer valid-token",
        "x-request-id": "rot-req-1",
      },
      payload: validRotationPayload(),
    });

    expect(response.headers["x-request-id"]).toBe("rot-req-1");
  });
});
