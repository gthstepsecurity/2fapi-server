// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import { registerVaultRoutes } from "../../../src/api-gateway/routes/vault.routes.js";
import { HandleOprfEvaluateUseCase } from "../../../packages/client-sdk/src/application/usecase/handle-oprf-evaluate.js";
import type { OprfKeyStore } from "../../../packages/client-sdk/src/domain/port/outgoing/oprf-key-store.js";
import type { VaultAttemptStore } from "../../../packages/client-sdk/src/domain/port/outgoing/vault-attempt-store.js";
import { registerRequestIdHook } from "../../../src/api-gateway/middleware/request-id.js";

function inMemoryKeyStore(): OprfKeyStore {
  const map = new Map<string, any>();
  return {
    save: async (k) => { map.set(`${k.clientId}:${k.deviceId}`, k); },
    findByDevice: async (c, d) => map.get(`${c}:${d}`) ?? null,
    delete: async (c, d) => { map.delete(`${c}:${d}`); },
  };
}

function inMemoryAttemptStore(): VaultAttemptStore {
  const map = new Map<string, any>();
  return {
    save: async (c) => { map.set(`${c.clientId}:${c.deviceId}`, c); },
    findByDevice: async (c, d) => map.get(`${c}:${d}`) ?? null,
    delete: async (c, d) => { map.delete(`${c}:${d}`); },
  };
}

const alwaysValidAuth = async () => true;

/** Parse the enveloped response: { data: hex } → inner JSON */
function parseEnvelope(body: string): any {
  const outer = JSON.parse(body);
  const buf = Buffer.from(outer.data, "hex");
  const jsonLen = buf.readUInt32BE(0);
  const jsonStr = buf.subarray(4, 4 + jsonLen).toString("utf-8");
  return JSON.parse(jsonStr);
}

describe("Vault Routes (indistinguishable responses)", () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    const oprfUseCase = new HandleOprfEvaluateUseCase(inMemoryKeyStore(), inMemoryAttemptStore());
    app = Fastify();
    registerRequestIdHook(app);
    registerVaultRoutes(app, oprfUseCase, alwaysValidAuth);
    await app.ready();
  });

  // --- R20-01: All responses wrapped in envelope ---

  it("all responses have 'data' field (envelope format)", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c1", device_id: "d1", auth_token: "v" } });
    expect(res.statusCode).toBe(200);
    const json = res.json();
    expect(json.data).toBeDefined();
    expect(typeof json.data).toBe("string");
    // data is hex-encoded, fixed length
    expect(json.data.length).toBe(960); // 480 bytes × 2 hex chars
  });

  it("envelope can be decoded to inner JSON", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c1", device_id: "d1", auth_token: "v" } });
    const inner = parseEnvelope(res.body);
    expect(inner.ok).toBe(true);
    expect(inner.seal_token).toBeDefined();
  });

  it("success and error envelopes have IDENTICAL outer size", async () => {
    const success = await app.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c1", device_id: "d1", auth_token: "v" } });
    const error = await app.inject({ method: "POST", url: "/v1/vault/seal", payload: {} });
    // Both outer envelopes are exactly the same size
    expect(success.body.length).toBe(error.body.length);
  });

  // --- R20-03: Wiped indistinguishable from allowed ---

  it("wiped response looks IDENTICAL to allowed at envelope level", async () => {
    // Seal + 3 failures → wipe
    await app.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c1", device_id: "d1", auth_token: "v" } });
    const blindedB64 = Buffer.from(new Uint8Array(32).fill(0xAA)).toString("base64");
    for (let i = 0; i < 3; i++) {
      const ev = await app.inject({ method: "POST", url: "/v1/vault/oprf-evaluate",
        payload: { client_id: "c1", device_id: "d1", blinded_point: blindedB64 } });
      const inner = parseEnvelope(ev.body);
      if (inner.eval_nonce) {
        await app.inject({ method: "POST", url: "/v1/vault/unseal-result",
          payload: { client_id: "c1", device_id: "d1", eval_nonce: inner.eval_nonce, status: "failure" } });
      }
    }

    // This evaluation is against a wiped vault
    const wipedRes = await app.inject({ method: "POST", url: "/v1/vault/oprf-evaluate",
      payload: { client_id: "c1", device_id: "d1", blinded_point: blindedB64 } });
    const wipedInner = parseEnvelope(wipedRes.body);

    // R20-03: wiped looks like "allowed" with populated fields
    expect(wipedInner.ok).toBe(true);
    expect(wipedInner.status).toBe("allowed"); // NOT "wiped"
    expect(wipedInner.evaluated).toBeDefined();
    expect(wipedInner.evaluated.length).toBeGreaterThan(0); // random, not empty
    expect(wipedInner.eval_nonce).toBeDefined();
    expect(wipedInner.eval_nonce.length).toBe(64); // random nonce (won't validate)

    // Client discovers wipe by trying to USE the nonce:
    const unsealResult = await app.inject({ method: "POST", url: "/v1/vault/unseal-result",
      payload: { client_id: "c1", device_id: "d1", eval_nonce: wipedInner.eval_nonce, status: "failure" } });
    const unsealInner = parseEnvelope(unsealResult.body);
    expect(unsealInner.ok).toBe(false); // nonce not found → client infers wipe
  });

  // --- Envelope size uniformity ---

  it("seal, evaluate, and unseal-result have identical envelope size", async () => {
    await app.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c1", device_id: "d1", auth_token: "v" } });

    const blindedB64 = Buffer.from(new Uint8Array(32).fill(0xAA)).toString("base64");

    const sizes = new Set<number>();

    const seal = await app.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c2", device_id: "d2", auth_token: "v" } });
    sizes.add(seal.body.length);

    const ev = await app.inject({ method: "POST", url: "/v1/vault/oprf-evaluate",
      payload: { client_id: "c1", device_id: "d1", blinded_point: blindedB64 } });
    sizes.add(ev.body.length);

    const evInner = parseEnvelope(ev.body);
    const unseal = await app.inject({ method: "POST", url: "/v1/vault/unseal-result",
      payload: { client_id: "c1", device_id: "d1", eval_nonce: evInner.eval_nonce, status: "success" } });
    sizes.add(unseal.body.length);

    // ALL sizes must be identical
    expect(sizes.size).toBe(1);
  });

  // --- Auth check (still works through envelope) ---

  it("unauthorized seal returns ok:false inside envelope", async () => {
    const strictApp = Fastify();
    registerRequestIdHook(strictApp);
    registerVaultRoutes(strictApp, new HandleOprfEvaluateUseCase(inMemoryKeyStore(), inMemoryAttemptStore()), async () => false);
    await strictApp.ready();
    const res = await strictApp.inject({ method: "POST", url: "/v1/vault/seal",
      payload: { client_id: "c1", device_id: "d1", auth_token: "bad" } });
    expect(res.statusCode).toBe(200);
    const inner = parseEnvelope(res.body);
    expect(inner.ok).toBe(false);
  });
});
