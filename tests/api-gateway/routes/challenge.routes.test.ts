// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubRequestChallenge,
  validBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Challenge Route — POST /v1/challenges", () => {
  let app: FastifyInstance;
  let requestChallenge: StubRequestChallenge;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    requestChallenge = result.deps.requestChallenge;
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Happy Path ---

  it("returns 200 with challenge data on success", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-payment-service",
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.challengeId).toBe("ch-42");
    expect(body.nonce).toBeDefined();
    expect(body.expiresAt).toBeDefined();
    expect(body.protocolVersion).toBe("1.0");
  });

  it("includes protocol version in response", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-payment-service",
        credential: validBase64(),
        channelBinding: validBase64(),
        protocolVersion: "1.0",
      },
    });

    const body = JSON.parse(response.body);
    expect(body.protocolVersion).toBe("1.0");
  });

  it("passes decoded bytes to the use case", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(requestChallenge.lastRequest).not.toBeNull();
    expect(requestChallenge.lastRequest!.clientIdentifier).toBe("alice-service");
    expect(requestChallenge.lastRequest!.credential).toBeInstanceOf(Uint8Array);
    expect(requestChallenge.lastRequest!.channelBinding).toBeInstanceOf(Uint8Array);
  });

  // --- Validation Errors ---

  it("returns 400 when clientIdentifier is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("clientIdentifier");
  });

  it("returns 400 when credential is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("credential");
  });

  it("returns 400 when channelBinding is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        credential: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("channelBinding");
  });

  it("returns 400 when credential has invalid base64", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        credential: "not-base64!!!",
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("base64");
    expect(body.detail).toContain("credential");
  });

  // --- Domain Errors ---

  it("returns 401 for challenge refusal (indistinguishable)", async () => {
    requestChallenge.setResponse({
      success: false,
      error: "challenge_refused",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:challenge-refused");
    expect(body.title).toBe("Unauthorized");
    expect(body.detail).toBe("Challenge request could not be completed");
  });

  it("returns 400 with supported versions for unsupported protocol version", async () => {
    requestChallenge.setResponse({
      success: false,
      error: "unsupported_protocol_version",
      supportedVersions: ["1.0"],
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        credential: validBase64(),
        channelBinding: validBase64(),
        protocolVersion: "0.1-deprecated",
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:unsupported-version");
    expect(body.detail).toContain("0.1-deprecated");
    expect(body.supportedVersions).toEqual(["1.0"]);
  });

  it("returns 429 for rate limiting with Retry-After header", async () => {
    requestChallenge.setResponse({
      success: false,
      error: "rate_limited",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/challenges",
      headers: { "content-type": "application/json" },
      payload: {
        clientIdentifier: "alice-service",
        credential: validBase64(),
        channelBinding: validBase64(),
      },
    });

    expect(response.statusCode).toBe(429);
    expect(response.headers["retry-after"]).toBeDefined();
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:rate-limited");
  });
});
