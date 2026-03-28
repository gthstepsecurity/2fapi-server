// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubEnrollClient,
  validBase64,
  validProofBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Enrollment Route — POST /v1/clients", () => {
  let app: FastifyInstance;
  let enrollClient: StubEnrollClient;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    enrollClient = result.deps.enrollClient;
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Happy Path ---

  it("returns 201 with referenceId and clientIdentifier on success", async () => {
    enrollClient.setResponse({
      success: true,
      referenceId: "ref-abc-123",
      clientIdentifier: "alice-payment-service",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-payment-service",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.body);
    expect(body.referenceId).toBe("ref-abc-123");
    expect(body.clientIdentifier).toBe("alice-payment-service");
  });

  it("includes Location header on success", async () => {
    enrollClient.setResponse({
      success: true,
      referenceId: "ref-abc-123",
      clientIdentifier: "alice-payment-service",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-payment-service",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.headers["location"]).toBe("/v1/clients/ref-abc-123");
  });

  it("includes X-Request-Id header", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: {
        "content-type": "application/json",
        "x-request-id": "my-req-1",
      },
      payload: {
        clientIdentifier: "alice-payment-service",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.headers["x-request-id"]).toBe("my-req-1");
  });

  it("passes decoded bytes to the use case", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(enrollClient.lastRequest).not.toBeNull();
    expect(enrollClient.lastRequest!.clientIdentifier).toBe("alice-service");
    expect(enrollClient.lastRequest!.commitmentBytes).toBeInstanceOf(Uint8Array);
  });

  it("ignores extra fields in request body", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
        extraField: "should be ignored",
      },
    });

    expect(response.statusCode).toBe(201);
  });

  // --- Validation Errors ---

  it("returns 400 when clientIdentifier is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:validation");
    expect(body.detail).toContain("clientIdentifier");
  });

  it("returns 400 when clientIdentifier is empty", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("empty");
  });

  it("returns 400 when clientIdentifier exceeds 128 characters", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "a".repeat(129),
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("maximum length");
  });

  it("returns 400 when clientIdentifier contains invalid characters", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice service!", // spaces and special chars
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("invalid characters");
  });

  it("returns 400 when commitment is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("commitment");
  });

  it("returns 400 when commitment has invalid base64", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        commitment: "not-valid-base64!!!",
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:validation");
    expect(body.detail).toContain("base64");
    expect(body.detail).toContain("commitment");
  });

  it("returns 400 when proofOfPossession is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        commitment: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("proofOfPossession");
  });

  it("returns 400 when proofOfPossession has invalid base64", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        commitment: validBase64(),
        proofOfPossession: "also-not-base64!!!",
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("base64");
    expect(body.detail).toContain("proofOfPossession");
  });

  // --- Domain Refusals ---

  it("returns 409 with indistinguishable error when enrollment is refused", async () => {
    enrollClient.setResponse({
      success: false,
      error: "enrollment_failed",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(409);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:enrollment-refused");
    expect(body.title).toBe("Enrollment Refused");
    expect(body.detail).toBe("Enrollment could not be completed");
  });

  it("accepts 1-character clientIdentifier", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "a",
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(201);
  });

  it("accepts 128-character clientIdentifier", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "a".repeat(128),
        commitment: validBase64(),
        proofOfPossession: validProofBase64(),
      },
    });

    expect(response.statusCode).toBe(201);
  });
});
