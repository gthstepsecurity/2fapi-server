// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import { registerRecoveryRoutes } from "../../../src/api-gateway/routes/recovery.routes.js";
import { registerRequestIdHook } from "../../../src/api-gateway/middleware/request-id.js";
import type {
  RecoverViaPhrase,
  RecoverViaPhraseRequest,
  RecoverViaPhraseResponse,
} from "../../../src/client-registration/domain/port/incoming/recover-via-phrase.js";
import { validBase64 } from "../test-helpers.js";

class StubRecoverViaPhrase implements RecoverViaPhrase {
  private _response: RecoverViaPhraseResponse = { success: true };
  lastRequest: RecoverViaPhraseRequest | null = null;

  setResponse(response: RecoverViaPhraseResponse): void {
    this._response = response;
  }

  async execute(request: RecoverViaPhraseRequest): Promise<RecoverViaPhraseResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

describe("Recovery Route — POST /v1/clients/:clientId/recover", () => {
  let app: FastifyInstance;
  let recoverViaPhrase: StubRecoverViaPhrase;

  beforeEach(() => {
    app = Fastify({ logger: false });
    registerRequestIdHook(app);
    recoverViaPhrase = new StubRecoverViaPhrase();
    registerRecoveryRoutes(app, recoverViaPhrase);
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Happy Path ---

  it("returns 200 with recovered: true on successful recovery", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["abandon", "ability", "able", "about", "above", "absent",
          "absorb", "abstract", "absurd", "abuse", "access", "accident"],
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.recovered).toBe(true);
    expect(body.clientIdentifier).toBe("alice-service");
  });

  it("passes correct parameters to use case", async () => {
    const twelveWords = ["abandon", "ability", "able", "about", "above", "absent",
      "absorb", "abstract", "absurd", "abuse", "access", "accident"];
    await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: twelveWords,
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(recoverViaPhrase.lastRequest).not.toBeNull();
    expect(recoverViaPhrase.lastRequest!.clientIdentifier).toBe("alice-service");
    expect(recoverViaPhrase.lastRequest!.words).toEqual(twelveWords);
  });

  // --- Failure Path ---

  it("returns 401 on failed recovery (indistinguishable)", async () => {
    recoverViaPhrase.setResponse({ success: false, error: "recovery_failed" });

    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["wrong", "words", "here", "that", "will", "not",
          "match", "the", "stored", "hash", "at", "all"],
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.body);
    expect(body.detail).toBe("recovery_failed");
  });

  // --- Validation ---

  it("returns 400 for invalid client identifier", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/inv@lid!/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["word1"],
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 when recoveryWords is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 when newCommitment is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["word1"],
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 when newCommitmentProof is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["word1"],
        newCommitment: validBase64(32),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 for 1000 recovery words (CB09)", async () => {
    const tooManyWords = Array.from({ length: 1000 }, (_, i) => `word${i}`);
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: tooManyWords,
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.detail).toContain("12, 18, or 24");
  });

  it("returns 400 for 5 recovery words (CB09)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["one", "two", "three", "four", "five"],
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 for invalid base64 in newCommitment", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/recover",
      headers: { "content-type": "application/json" },
      payload: {
        recoveryWords: ["word1"],
        newCommitment: "not-valid-base64!!!",
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });
});
