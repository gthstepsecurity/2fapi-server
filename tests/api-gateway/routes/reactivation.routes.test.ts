// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import { registerReactivationRoutes } from "../../../src/api-gateway/routes/reactivation.routes.js";
import { registerRequestIdHook } from "../../../src/api-gateway/middleware/request-id.js";
import type {
  ReactivateViaExternal,
  ReactivateViaExternalRequest,
  ReactivateViaExternalResponse,
} from "../../../src/client-registration/domain/port/incoming/reactivate-via-external.js";
import { validBase64 } from "../test-helpers.js";

class StubReactivateViaExternal implements ReactivateViaExternal {
  private _response: ReactivateViaExternalResponse = { success: true };
  lastRequest: ReactivateViaExternalRequest | null = null;

  setResponse(response: ReactivateViaExternalResponse): void {
    this._response = response;
  }

  async execute(request: ReactivateViaExternalRequest): Promise<ReactivateViaExternalResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

describe("Reactivation Route — POST /v1/clients/:clientId/reactivate", () => {
  let app: FastifyInstance;
  let reactivateViaExternal: StubReactivateViaExternal;

  beforeEach(() => {
    app = Fastify({ logger: false });
    registerRequestIdHook(app);
    reactivateViaExternal = new StubReactivateViaExternal();
    registerReactivationRoutes(app, reactivateViaExternal);
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Happy Path ---

  it("returns 200 with reactivated: true on successful reactivation", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
      payload: {
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.reactivated).toBe(true);
  });

  it("passes correct parameters to use case", async () => {
    await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
      payload: {
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(reactivateViaExternal.lastRequest).not.toBeNull();
    expect(reactivateViaExternal.lastRequest!.clientIdentifier).toBe("alice-service");
    expect(reactivateViaExternal.lastRequest!.adminIdentity).toBe("CN=bob-admin,O=2fapi");
  });

  // --- Failure Path ---

  it("returns 401 on failed reactivation (indistinguishable)", async () => {
    reactivateViaExternal.setResponse({ success: false, error: "reactivation_failed" });

    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
      payload: {
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(401);
  });

  // --- Validation ---

  it("returns 403 without admin identity header", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/reactivate",
      headers: { "content-type": "application/json" },
      payload: {
        newCommitment: validBase64(32),
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.detail).toBe("Administrator privileges required");
  });

  it("returns 400 for invalid client identifier", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/inv@lid!/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
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
      url: "/v1/clients/alice-service/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
      payload: {
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 when newCommitmentProof is missing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
      payload: {
        newCommitment: validBase64(32),
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it("returns 400 for invalid base64 in newCommitment", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/clients/alice-service/reactivate",
      headers: {
        "content-type": "application/json",
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
      payload: {
        newCommitment: "not-valid!!!",
        newCommitmentProof: validBase64(96),
      },
    });

    expect(response.statusCode).toBe(400);
  });
});
