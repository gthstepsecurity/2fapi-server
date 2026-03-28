// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  createTestDeps,
  type TestDeps,
} from "../api-gateway/test-helpers.js";
import { createServer, createDevelopmentServer } from "../../src/api-gateway/server.js";

describe("FIX 4 — Channel Binding in Resource/Rotation Routes", () => {
  let app: FastifyInstance;
  let deps: TestDeps;

  afterEach(async () => {
    if (app) await app.close();
  });

  describe("Resource route — strict mode", () => {
    beforeEach(() => {
      deps = createTestDeps();
      app = createServer(deps, {
        serviceAudience: "test-service",
        channelBindingMode: "strict",
        rateLimiting: { trustedProxies: [] },
      });
    });

    it("returns 401 when X-Channel-Binding header is absent in strict mode", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/resources/payment-config",
        headers: {
          authorization: "Bearer valid-token-abc",
        },
      });

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.detail).toContain("channel binding");
    });

    it("passes X-Channel-Binding header to validateToken in strict mode", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/resources/payment-config",
        headers: {
          authorization: "Bearer valid-token-abc",
          "x-channel-binding": "c29tZS1jaGFubmVsLWJpbmRpbmc=",
        },
      });

      expect(response.statusCode).toBe(200);
      expect(deps.validateToken.lastRequest).not.toBeNull();
      expect(deps.validateToken.lastRequest!.channelBindingHash).toBe(
        "c29tZS1jaGFubmVsLWJpbmRpbmc=",
      );
    });
  });

  describe("Resource route — permissive mode", () => {
    beforeEach(() => {
      deps = createTestDeps();
      app = createServer(deps, {
        serviceAudience: "test-service",
        channelBindingMode: "permissive",
        rateLimiting: { trustedProxies: [] },
      });
    });

    it("allows request without X-Channel-Binding in permissive mode", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/resources/payment-config",
        headers: {
          authorization: "Bearer valid-token-abc",
        },
      });

      expect(response.statusCode).toBe(200);
      // In permissive mode, channelBindingHash should be the sentinel "__channel_binding_skipped__"
      expect(deps.validateToken.lastRequest!.channelBindingHash).toBe(
        "__channel_binding_skipped__",
      );
    });
  });

  describe("Rotation route — strict mode", () => {
    beforeEach(() => {
      deps = createTestDeps();
      app = createServer(deps, {
        serviceAudience: "test-service",
        channelBindingMode: "strict",
        rateLimiting: { trustedProxies: [] },
      });
    });

    it("returns 401 when X-Channel-Binding header is absent in strict mode", async () => {
      const response = await app.inject({
        method: "PUT",
        url: "/v1/clients/client-1/commitment",
        headers: {
          authorization: "Bearer valid-token-abc",
          "content-type": "application/json",
        },
        payload: JSON.stringify({
          currentProof: Buffer.from(new Uint8Array(32).fill(1)).toString("base64"),
          newCommitment: Buffer.from(new Uint8Array(32).fill(2)).toString("base64"),
          newCommitmentProof: Buffer.from(new Uint8Array(32).fill(3)).toString("base64"),
        }),
      });

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.detail).toContain("channel binding");
    });

    it("passes X-Channel-Binding header to validateToken in strict mode", async () => {
      const response = await app.inject({
        method: "PUT",
        url: "/v1/clients/client-1/commitment",
        headers: {
          authorization: "Bearer valid-token-abc",
          "content-type": "application/json",
          "x-channel-binding": "cm90YXRpb24tYmluZGluZw==",
        },
        payload: JSON.stringify({
          currentProof: Buffer.from(new Uint8Array(32).fill(1)).toString("base64"),
          newCommitment: Buffer.from(new Uint8Array(32).fill(2)).toString("base64"),
          newCommitmentProof: Buffer.from(new Uint8Array(32).fill(3)).toString("base64"),
        }),
      });

      expect(deps.validateToken.lastRequest).not.toBeNull();
      expect(deps.validateToken.lastRequest!.channelBindingHash).toBe(
        "cm90YXRpb24tYmluZGluZw==",
      );
    });
  });

  describe("Default channel binding mode (CF01)", () => {
    it("defaults to strict when not configured", async () => {
      deps = createTestDeps();
      app = createServer(deps, {
        serviceAudience: "test-service",
        rateLimiting: { trustedProxies: [] },
      });

      // Without explicit channelBindingMode, default is "strict" (CF01)
      // So requesting a resource without X-Channel-Binding should fail
      const response = await app.inject({
        method: "GET",
        url: "/v1/resources/payment-config",
        headers: {
          authorization: "Bearer valid-token-abc",
        },
      });
      expect(response.statusCode).toBe(401);
    });
  });
});
