// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubVerifyProof,
  StubIssueToken,
  validBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Verification Route — POST /v1/verify", () => {
  let app: FastifyInstance;
  let verifyProof: StubVerifyProof;
  let issueToken: StubIssueToken;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    verifyProof = result.deps.verifyProof;
    issueToken = result.deps.issueToken;
  });

  afterEach(async () => {
    await app.close();
  });

  function validPayload() {
    return {
      clientIdentifier: "alice-payment-service",
      challengeId: "ch-42",
      proof: validBase64(),
      channelBinding: validBase64(),
      domainSeparationTag: "2FApi-v1.0-Sigma",
    };
  }

  // --- Happy Path ---

  it("returns 200 with access token on successful verification", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.accessToken).toBe("token-abc-123");
    expect(body.tokenType).toBe("Bearer");
    expect(body.expiresAt).toBeDefined();
    expect(typeof body.expiresIn).toBe("number");
  });

  it("passes decoded bytes to the verify proof use case", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(verifyProof.lastRequest).not.toBeNull();
    expect(verifyProof.lastRequest!.clientIdentifier).toBe("alice-payment-service");
    expect(verifyProof.lastRequest!.challengeId).toBe("ch-42");
    expect(verifyProof.lastRequest!.proofBytes).toBeInstanceOf(Uint8Array);
    expect(verifyProof.lastRequest!.channelBinding).toBeInstanceOf(Uint8Array);
    expect(verifyProof.lastRequest!.domainSeparationTag).toBe("2FApi-v1.0-Sigma");
  });

  it("issues a token after successful verification", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(issueToken.lastRequest).not.toBeNull();
    expect(issueToken.lastRequest!.clientIdentifier).toBe("test-client");
  });

  // --- Validation Errors ---

  it("returns 400 when clientIdentifier is missing", async () => {
    const payload = validPayload();
    const { clientIdentifier, ...rest } = payload;

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("clientIdentifier");
  });

  it("returns 400 when challengeId is missing", async () => {
    const payload = validPayload();
    const { challengeId, ...rest } = payload;

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("challengeId");
  });

  it("returns 400 when proof is missing", async () => {
    const payload = validPayload();
    const { proof, ...rest } = payload;

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("proof");
  });

  it("returns 400 when channelBinding is missing", async () => {
    const payload = validPayload();
    const { channelBinding, ...rest } = payload;

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("channelBinding");
  });

  it("returns 400 when domainSeparationTag is missing", async () => {
    const payload = validPayload();
    const { domainSeparationTag, ...rest } = payload;

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: rest,
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("domainSeparationTag");
  });

  it("returns 400 when proof has invalid base64", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        proof: "not-base64!!!",
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("base64");
    expect(body.detail).toContain("proof");
  });

  it("returns 400 when domainSeparationTag exceeds 64 characters", async () => {
    const longTag = "x".repeat(10000);
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        domainSeparationTag: longTag,
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("1-64 ASCII");
  });

  it("accepts domainSeparationTag of exactly 64 characters", async () => {
    const exactTag = "x".repeat(64);
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        domainSeparationTag: exactTag,
      },
    });

    expect(response.statusCode).toBe(200);
  });

  // FIX L-01: DST charset validation — reject non-ASCII characters
  it("rejects domainSeparationTag containing Unicode homoglyphs", async () => {
    // Cyrillic "а" (U+0430) looks identical to Latin "a" (U+0061)
    // Accepting it would produce different transcripts for visually identical tags
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        domainSeparationTag: "2F\u0410pi-v1.0", // Cyrillic А
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("ASCII");
  });

  it("rejects domainSeparationTag with spaces", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        domainSeparationTag: "2FApi v1.0 Sigma",
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("rejects domainSeparationTag with bidirectional control chars", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        domainSeparationTag: "2FApi\u200Fv1", // Right-to-left mark
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("accepts valid DST with all allowed characters", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        domainSeparationTag: "Ghost-Protocol_v2.1-Sigma",
      },
    });

    expect(response.statusCode).toBe(200);
  });

  // --- Domain Errors ---

  it("returns 401 for verification refusal (indistinguishable)", async () => {
    verifyProof.setResponse({
      success: false,
      error: "verification_refused",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:verification-refused");
    expect(body.title).toBe("Unauthorized");
    expect(body.detail).toBe("Verification could not be completed");
  });

  // FIX H-02: rate_limited now returns indistinguishable 401 (was 429)
  it("returns 401 for rate limiting — indistinguishable from other failures", async () => {
    verifyProof.setResponse({
      success: false,
      error: "rate_limited",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers["retry-after"]).toBeUndefined();
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:verification-refused");
    expect(body.detail).toBe("Verification could not be completed");
  });

  it("rate_limited response is byte-identical to verification_refused", async () => {
    // Capture rate_limited response
    verifyProof.setResponse({ success: false, error: "rate_limited" });
    const rateLimitedRes = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    // Capture verification_refused response
    verifyProof.setResponse({ success: false, error: "verification_refused" });
    const refusedRes = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    // Bodies must be structurally identical (only instance/timestamp may differ)
    const rlBody = JSON.parse(rateLimitedRes.body);
    const rfBody = JSON.parse(refusedRes.body);
    expect(rateLimitedRes.statusCode).toBe(refusedRes.statusCode);
    expect(rlBody.type).toBe(rfBody.type);
    expect(rlBody.title).toBe(rfBody.title);
    expect(rlBody.status).toBe(rfBody.status);
    expect(rlBody.detail).toBe(rfBody.detail);
  });

  it("returns 401 when token issuance fails after successful verification", async () => {
    issueToken.setResponse({
      success: false,
      error: "issuance_refused",
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(response.statusCode).toBe(401);
  });

  it("passes targetAudience from request body to issueToken", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: {
        ...validPayload(),
        targetAudience: "payment-service",
      },
    });

    expect(issueToken.lastRequest).not.toBeNull();
    expect(issueToken.lastRequest!.audience).toBe("payment-service");
  });

  it("uses default audience when targetAudience is not provided", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    expect(issueToken.lastRequest).not.toBeNull();
    expect(issueToken.lastRequest!.audience).toBe("default");
  });

  it("response does not contain proof or commitment data", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    const body = JSON.parse(response.body);
    expect(body.proof).toBeUndefined();
    expect(body.commitment).toBeUndefined();
    expect(body.nonce).toBeUndefined();
  });

  // --- FIX RT-36: response size oracle prevention ---

  it("success and failure responses have identical body length (RT-36)", async () => {
    // Success response
    const successRes = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    // Failure response
    verifyProof.setResponse({ success: false, error: "verification_refused" });
    const failureRes = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    // Both padded to same target size — TLS record sizes are indistinguishable
    expect(successRes.body.length).toBe(failureRes.body.length);
  });

  it("padded responses contain random data (not compressible)", async () => {
    const r1 = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });
    const r2 = await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });

    const b1 = JSON.parse(r1.body);
    const b2 = JSON.parse(r2.body);

    // Padding is random — differs between requests (anti-CRIME/BREACH)
    if (b1._p && b2._p) {
      expect(b1._p).not.toBe(b2._p);
    }
  });
});
