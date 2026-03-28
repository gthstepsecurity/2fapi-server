// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";

/**
 * Infrastructure adapter: sends ALL vault requests through a single endpoint
 * with fixed-size enveloped bodies (R23-01, R23-02, R23-04 fix).
 *
 * Every request:
 *   POST /v1/vault
 *   Authorization: Bearer <token or dummy, fixed length>
 *   Body: { data: "<960 hex chars>" }
 *
 * The operation type (seal, evaluate, unseal-result, dummy) is INSIDE
 * the encrypted envelope. An observer sees identical requests.
 */

const ENVELOPE_PLAINTEXT_SIZE = 480;
const DUMMY_TOKEN_LENGTH = 256; // fixed JWT-like length

export class UniformHttpClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetch: typeof globalThis.fetch,
  ) {}

  /**
   * Send a vault operation through the single uniform endpoint.
   * All requests have identical external characteristics.
   */
  async send(operation: VaultOperation, authToken?: string): Promise<VaultResponse> {
    const body = envelopeRequest(operation);
    const token = authToken ?? generateDummyToken();

    const response = await this.fetch(`${this.baseUrl}/v1/vault`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${padToken(token)}`,
      },
      body: JSON.stringify(body),
    });

    const responseBody = await response.json() as { data: string };
    return parseEnvelope(responseBody.data);
  }

  /**
   * Send a dummy request (for request count normalization).
   * Identical to a real request from the outside.
   */
  async sendDummy(): Promise<void> {
    await this.send({ op: "dummy" });
  }
}

// --- Envelope encoding/decoding ---

function envelopeRequest(operation: VaultOperation): { data: string } {
  const json = JSON.stringify(operation);
  const jsonBytes = Buffer.from(json, "utf-8");
  const plaintext = Buffer.alloc(ENVELOPE_PLAINTEXT_SIZE);

  plaintext.writeUInt32BE(jsonBytes.length, 0);
  jsonBytes.copy(plaintext, 4, 0, Math.min(jsonBytes.length, ENVELOPE_PLAINTEXT_SIZE - 4));

  const remaining = ENVELOPE_PLAINTEXT_SIZE - 4 - jsonBytes.length;
  if (remaining > 0) {
    randomBytes(remaining).copy(plaintext, 4 + jsonBytes.length);
  }

  return { data: plaintext.toString("hex") };
}

function parseEnvelope(hex: string): VaultResponse {
  const buf = Buffer.from(hex, "hex");
  const jsonLen = buf.readUInt32BE(0);
  const jsonStr = buf.subarray(4, 4 + jsonLen).toString("utf-8");
  return JSON.parse(jsonStr);
}

function padToken(token: string): string {
  if (token.length >= DUMMY_TOKEN_LENGTH) return token.slice(0, DUMMY_TOKEN_LENGTH);
  return token + "x".repeat(DUMMY_TOKEN_LENGTH - token.length);
}

function generateDummyToken(): string {
  return randomBytes(DUMMY_TOKEN_LENGTH / 2).toString("hex");
}

// --- Types ---

export type VaultOperation =
  | { op: "seal"; client_id: string; device_id: string; auth_token?: string }
  | { op: "evaluate"; client_id: string; device_id: string; blinded_point: string; seal_token?: string }
  | { op: "unseal_result"; client_id: string; device_id: string; eval_nonce: string; status: "success" | "failure" }
  | { op: "dummy" };

export type VaultResponse = Record<string, unknown>;
