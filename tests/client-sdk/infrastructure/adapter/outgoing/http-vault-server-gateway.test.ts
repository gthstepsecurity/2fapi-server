// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { HttpVaultServerGateway } from "../../../../../packages/client-sdk/src/infrastructure/adapter/outgoing/http-vault-server-gateway.js";
import type { UnsealResponse } from "../../../../../packages/client-sdk/src/domain/port/outgoing/vault-server-gateway.js";

// --- Stub HTTP client ---

type StubResponse = {
  readonly ok: boolean;
  readonly status: number;
  readonly json: () => Promise<unknown>;
};

type FetchFn = (url: string, init: RequestInit) => Promise<StubResponse>;

function createStubFetch(handler: FetchFn): FetchFn {
  return handler;
}

describe("HttpVaultServerGateway", () => {
  const baseUrl = "https://api.example.com";

  // --- FIX L-02: HTTPS enforcement ---

  describe("HTTPS enforcement (FIX L-02)", () => {
    it("throws when baseUrl uses HTTP without allowInsecure", () => {
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({}),
      }));
      expect(
        () => new HttpVaultServerGateway("http://api.example.com", fetch as unknown as typeof globalThis.fetch),
      ).toThrow("HTTPS");
    });

    it("accepts HTTPS baseUrl", () => {
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({}),
      }));
      expect(
        () => new HttpVaultServerGateway("https://api.example.com", fetch as unknown as typeof globalThis.fetch),
      ).not.toThrow();
    });

    it("allows HTTP when allowInsecure is true (dev only)", () => {
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({}),
      }));
      expect(
        () => new HttpVaultServerGateway(
          "http://localhost:3000",
          fetch as unknown as typeof globalThis.fetch,
          { allowInsecure: true },
        ),
      ).not.toThrow();
    });
  });

  // --- requestSeal ---

  describe("requestSeal", () => {
    it("sends POST /v1/vault/seal with client_id and device_id", async () => {
      let capturedUrl = "";
      let capturedBody: unknown = null;

      const fetch = createStubFetch(async (url, init) => {
        capturedUrl = url;
        capturedBody = JSON.parse(init.body as string);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            pepper: "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=", // base64 of 32 bytes
            device_id: "dev-abc123",
          }),
        };
      });

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      await gateway.requestSeal({ clientId: "client-1", deviceId: "dev-abc123" });

      expect(capturedUrl).toBe("https://api.example.com/v1/vault/seal");
      expect(capturedBody).toEqual({ client_id: "client-1", device_id: "dev-abc123" });
    });

    it("returns pepper as Uint8Array", async () => {
      const pepperBase64 = Buffer.from(new Uint8Array(32).fill(0xBB)).toString("base64");
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ pepper: pepperBase64, device_id: "dev-abc123" }),
      }));

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      const result = await gateway.requestSeal({ clientId: "c1", deviceId: "dev-abc123" });

      expect(result.pepper.length).toBe(32);
      expect(result.pepper[0]).toBe(0xBB);
      expect(result.deviceId).toBe("dev-abc123");
    });

    it("throws on server error", async () => {
      const fetch = createStubFetch(async () => ({
        ok: false,
        status: 500,
        json: async () => ({ error: "internal" }),
      }));

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      await expect(gateway.requestSeal({ clientId: "c1", deviceId: "d1" }))
        .rejects.toThrow();
    });
  });

  // --- requestUnseal ---

  describe("requestUnseal", () => {
    it("returns allowed with pepper and attempts remaining", async () => {
      const pepperBase64 = Buffer.from(new Uint8Array(32).fill(0xCC)).toString("base64");
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          status: "allowed",
          pepper: pepperBase64,
          attempts_remaining: 2,
        }),
      }));

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      const result = await gateway.requestUnseal({ clientId: "c1", deviceId: "d1" });

      expect(result.status).toBe("allowed");
      if (result.status === "allowed") {
        expect(result.pepper[0]).toBe(0xCC);
        expect(result.attemptsRemaining).toBe(2);
      }
    });

    it("returns wiped when server says wiped", async () => {
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ status: "wiped" }),
      }));

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      const result = await gateway.requestUnseal({ clientId: "c1", deviceId: "d1" });
      expect(result.status).toBe("wiped");
    });

    it("returns vault_expired when server says expired", async () => {
      const fetch = createStubFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ status: "vault_expired" }),
      }));

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      const result = await gateway.requestUnseal({ clientId: "c1", deviceId: "d1" });
      expect(result.status).toBe("vault_expired");
    });

    it("throws on network error", async () => {
      const fetch = createStubFetch(async () => { throw new Error("network"); });

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      await expect(gateway.requestUnseal({ clientId: "c1", deviceId: "d1" }))
        .rejects.toThrow();
    });
  });

  // --- reportUnsealFailure ---

  describe("reportUnsealFailure", () => {
    it("sends POST /v1/vault/unseal-failed", async () => {
      let capturedUrl = "";
      const fetch = createStubFetch(async (url) => {
        capturedUrl = url;
        return { ok: true, status: 204, json: async () => ({}) };
      });

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      await gateway.reportUnsealFailure({ clientId: "c1", deviceId: "d1" });
      expect(capturedUrl).toBe("https://api.example.com/v1/vault/unseal-failed");
    });
  });

  // --- reportAuthSuccess ---

  describe("reportAuthSuccess", () => {
    it("sends POST /v1/vault/auth-success", async () => {
      let capturedUrl = "";
      const fetch = createStubFetch(async (url) => {
        capturedUrl = url;
        return { ok: true, status: 204, json: async () => ({}) };
      });

      const gateway = new HttpVaultServerGateway(baseUrl, fetch as unknown as typeof globalThis.fetch);
      await gateway.reportAuthSuccess({ clientId: "c1", deviceId: "d1" });
      expect(capturedUrl).toBe("https://api.example.com/v1/vault/auth-success");
    });
  });
});
