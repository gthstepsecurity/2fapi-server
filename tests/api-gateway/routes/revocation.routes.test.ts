// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubRevokeClient,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

describe("Revocation Route — DELETE /v1/clients/:clientId", () => {
  let app: FastifyInstance;
  let revokeClient: StubRevokeClient;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    revokeClient = result.deps.revokeClient;
  });

  afterEach(async () => {
    await app.close();
  });

  // --- Happy Path ---

  it("returns 204 on successful revocation", async () => {
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/alice-payment-service",
      headers: {
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
    });

    expect(response.statusCode).toBe(204);
    expect(response.body).toBe("");
  });

  it("passes correct clientId and adminIdentity to use case", async () => {
    await app.inject({
      method: "DELETE",
      url: "/v1/clients/alice-payment-service",
      headers: {
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
    });

    expect(revokeClient.lastRequest).not.toBeNull();
    expect(revokeClient.lastRequest!.clientIdentifier).toBe("alice-payment-service");
    expect(revokeClient.lastRequest!.adminIdentity).toBe("CN=bob-admin,O=2fapi");
  });

  it("returns 204 for unknown client (indistinguishable)", async () => {
    revokeClient.setResponse({
      success: false,
      error: "revocation_failed",
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/nonexistent-service",
      headers: {
        "x-admin-identity": "CN=bob-admin,O=2fapi",
      },
    });

    // The route always returns 204 regardless of domain result
    expect(response.statusCode).toBe(204);
  });

  // --- Error Cases ---

  it("returns 403 without admin identity header", async () => {
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/alice-payment-service",
    });

    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.type).toBe("urn:2fapi:error:forbidden");
    expect(body.title).toBe("Forbidden");
    expect(body.detail).toBe("Administrator privileges required");
  });

  it("includes X-Request-Id header", async () => {
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/clients/alice-payment-service",
      headers: {
        "x-admin-identity": "CN=bob-admin,O=2fapi",
        "x-request-id": "rev-req-1",
      },
    });

    expect(response.headers["x-request-id"]).toBe("rev-req-1");
  });
});
