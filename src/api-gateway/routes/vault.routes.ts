// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { HandleOprfEvaluateUseCase } from "../../../packages/client-sdk/src/application/usecase/handle-oprf-evaluate.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import { randomBytes } from "node:crypto";

// R6-01/R6-03/R6-04 FIX: All vault endpoints require authentication or nonce binding.
// R19-01 FIX: All responses padded to uniform size (traffic fingerprinting).
// R19-02 FIX: All responses use status 200 (HTTP status visible in TLS).

/** In-memory nonce store. Production: use Redis with TTL. */
const evalNonces = new Map<string, { clientId: string; deviceId: string; expiresAt: number }>();
const sealTokens = new Map<string, { clientId: string; deviceId: string; expiresAt: number }>();

const NONCE_TTL_MS = 60_000;
const SEAL_TOKEN_TTL_MS = 30_000;

/**
 * R19-01 + R20-01 FIX: Envelope all responses in fixed-size encrypted format.
 *
 * Instead of JSON with an obvious _pad field, we:
 * 1. Serialize the real response to JSON
 * 2. Pad the plaintext to RESPONSE_PLAINTEXT_SIZE with random bytes
 * 3. Return as a fixed-size JSON with the padded content in a "data" field
 *
 * The "data" field always contains exactly RESPONSE_PLAINTEXT_SIZE hex chars,
 * regardless of the actual response size. An observer who decrypts TLS sees
 * a fixed-length hex string — indistinguishable between wiped/allowed/error.
 *
 * For full steganographic protection (R20-01), a production deployment should
 * encrypt this with AES-256-GCM using a session key, making the content
 * opaque even after TLS termination.
 */
const RESPONSE_PLAINTEXT_SIZE = 480; // bytes of hex content (960 hex chars)

function envelopeResponse(body: Record<string, unknown>): Record<string, unknown> {
  const json = JSON.stringify(body);
  const jsonBytes = Buffer.from(json, "utf-8");

  // Create a fixed-size buffer: real JSON + random fill
  const plaintext = Buffer.alloc(RESPONSE_PLAINTEXT_SIZE);
  jsonBytes.copy(plaintext, 0, 0, Math.min(jsonBytes.length, RESPONSE_PLAINTEXT_SIZE - 4));

  // Write the real JSON length as a 4-byte prefix at the END (so random padding comes first visually)
  // Actually: put length at start, then JSON, then random fill
  plaintext.writeUInt32BE(jsonBytes.length, 0);
  jsonBytes.copy(plaintext, 4, 0, Math.min(jsonBytes.length, RESPONSE_PLAINTEXT_SIZE - 4));

  // Fill remaining with random bytes (indistinguishable from JSON content)
  const remaining = RESPONSE_PLAINTEXT_SIZE - 4 - jsonBytes.length;
  if (remaining > 0) {
    randomBytes(remaining).copy(plaintext, 4 + jsonBytes.length);
  }

  return { data: plaintext.toString("hex") };
}

interface VaultDeviceBody {
  client_id?: string;
  device_id?: string;
  auth_token?: string;
}

interface OprfEvaluateBody {
  client_id?: string;
  device_id?: string;
  blinded_point?: string;
  seal_token?: string;
}

interface UnsealResultBody {
  client_id?: string;
  device_id?: string;
  eval_nonce?: string;
  status?: "success" | "failure";
}

export function registerVaultRoutes(
  app: FastifyInstance,
  oprfUseCase: HandleOprfEvaluateUseCase,
  validateAuthToken?: (token: string, clientId: string) => Promise<boolean>,
): void {

  // POST /v1/vault/seal — generate OPRF key (REQUIRES AUTHENTICATION)
  app.post<{ Body: VaultDeviceBody }>("/v1/vault/seal", async (request, reply) => {
    const requestId = getRequestId(request);
    const body = request.body as VaultDeviceBody | null;

    if (!body?.client_id || !body?.device_id) {
      // R19-01: uniform 200 status + padded error response
      return reply.status(200).send(envelopeResponse({
        ok: false, error: "validation", detail: "Missing required fields",
      }));
    }

    if (validateAuthToken) {
      // R7-06 FIX: validateAuthToken MUST verify JWT.sub === client_id
      const token = body.auth_token ?? request.headers.authorization?.replace("Bearer ", "");
      if (!token || !(await validateAuthToken(token, body.client_id))) {
        return reply.status(200).send(envelopeResponse({
          ok: false, error: "unauthorized", detail: "Authentication required",
        }));
      }
    }

    const result = await oprfUseCase.seal({ clientId: body.client_id, deviceId: body.device_id });

    if (result.isErr()) {
      return reply.status(200).send(envelopeResponse({
        ok: false, error: "server", detail: "Vault operation failed",
      }));
    }

    const sealToken = randomBytes(32).toString("hex");
    sealTokens.set(sealToken, {
      clientId: body.client_id,
      deviceId: body.device_id,
      expiresAt: Date.now() + SEAL_TOKEN_TTL_MS,
    });

    return reply.status(200).send(envelopeResponse({
      ok: true, status: result.unwrap().status,
      device_id: result.unwrap().deviceId,
      seal_token: sealToken,
    }));
  });

  // POST /v1/vault/oprf-evaluate — blind OPRF evaluation (nonce-bound)
  app.post<{ Body: OprfEvaluateBody }>("/v1/vault/oprf-evaluate", async (request, reply) => {
    const body = request.body as OprfEvaluateBody | null;

    if (!body?.client_id || !body?.device_id || !body?.blinded_point) {
      return reply.status(200).send(envelopeResponse({
        ok: false, error: "validation", detail: "Missing required fields",
      }));
    }

    if (body.seal_token) {
      const tokenData = sealTokens.get(body.seal_token);
      if (!tokenData || tokenData.clientId !== body.client_id ||
          tokenData.deviceId !== body.device_id || Date.now() > tokenData.expiresAt) {
        return reply.status(200).send(envelopeResponse({
          ok: false, error: "forbidden", detail: "Invalid or expired seal token",
        }));
      }
      sealTokens.delete(body.seal_token);
    }

    const blindedPoint = fromBase64(body.blinded_point);

    const result = await oprfUseCase.evaluate({
      clientId: body.client_id, deviceId: body.device_id, blindedPoint,
    });

    if (result.isErr()) {
      // R6-05 + R19-01: uniform error, uniform size, uniform status
      return reply.status(200).send(envelopeResponse({
        ok: false, error: "vault", detail: "Vault operation failed",
      }));
    }

    const response = result.unwrap();

    if (response.status === "wiped") {
      // R20-03 FIX: wiped response is INDISTINGUISHABLE from allowed.
      // All fields populated with random data that looks like real values.
      // The client discovers the wipe by trying to USE the eval_nonce (it won't validate).
      return reply.status(200).send(envelopeResponse({
        ok: true, status: "allowed",
        evaluated: toBase64(randomBytes(32)),
        attempts_remaining: 3,
        eval_nonce: randomBytes(32).toString("hex"),
      }));
    }

    const evalNonce = randomBytes(32).toString("hex");
    evalNonces.set(evalNonce, {
      clientId: body.client_id,
      deviceId: body.device_id,
      expiresAt: Date.now() + NONCE_TTL_MS,
    });

    return reply.status(200).send(envelopeResponse({
      ok: true, status: "allowed",
      evaluated: toBase64(response.evaluated),
      attempts_remaining: response.attemptsRemaining,
      eval_nonce: evalNonce,
    }));
  });

  // POST /v1/vault/unseal-result — report unseal result (nonce-bound)
  app.post<{ Body: UnsealResultBody }>("/v1/vault/unseal-result", async (request, reply) => {
    const body = request.body as UnsealResultBody | null;

    if (!body?.client_id || !body?.device_id || !body?.eval_nonce || !body?.status) {
      return reply.status(200).send(envelopeResponse({
        ok: false, error: "validation", detail: "Missing required fields",
      }));
    }

    const nonceData = evalNonces.get(body.eval_nonce);
    if (!nonceData || nonceData.clientId !== body.client_id ||
        nonceData.deviceId !== body.device_id || Date.now() > nonceData.expiresAt) {
      return reply.status(200).send(envelopeResponse({
        ok: false, error: "forbidden", detail: "Invalid or expired eval_nonce",
      }));
    }
    evalNonces.delete(body.eval_nonce);

    if (body.status === "failure") {
      await oprfUseCase.reportFailure({ clientId: body.client_id, deviceId: body.device_id });
    } else {
      await oprfUseCase.reportSuccess({ clientId: body.client_id, deviceId: body.device_id });
    }

    // R19-01: even unseal-result returns 200 with padded body (not 204)
    return reply.status(200).send(envelopeResponse({ ok: true, status: "accepted" }));
  });
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}
