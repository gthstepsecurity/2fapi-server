// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  VaultServerGateway,
  SealRequest,
  SealResponse,
  UnsealRequest,
  UnsealResponse,
  UnsealFailureReport,
  AuthSuccessReport,
} from "../../../domain/port/outgoing/vault-server-gateway.js";

/**
 * Infrastructure adapter: communicates with the 2FApi server for vault operations.
 * Handles pepper delivery, attempt counter, and lifecycle notifications.
 */
export class HttpVaultServerGateway implements VaultServerGateway {
  /**
   * FIX L-02: enforce HTTPS in production.
   *
   * Plaintext HTTP exposes pepper, unseal status, and OPRF evaluations
   * to any network observer — defeating the entire zero-knowledge property.
   * Set `allowInsecure` only for local development / test harness.
   */
  constructor(
    private readonly baseUrl: string,
    private readonly fetch: typeof globalThis.fetch,
    options?: { allowInsecure?: boolean },
  ) {
    if (
      !options?.allowInsecure &&
      !baseUrl.startsWith("https://")
    ) {
      throw new Error(
        "HttpVaultServerGateway requires HTTPS. " +
        "Pass { allowInsecure: true } for local development only.",
      );
    }
  }

  async requestSeal(params: SealRequest): Promise<SealResponse> {
    const response = await this.post("/v1/vault/seal", {
      client_id: params.clientId,
      device_id: params.deviceId,
    });

    const body = await response.json() as { pepper: string; device_id: string };
    return {
      pepper: fromBase64(body.pepper),
      deviceId: body.device_id,
    };
  }

  async requestUnseal(params: UnsealRequest): Promise<UnsealResponse> {
    const response = await this.post("/v1/vault/unseal-attempt", {
      client_id: params.clientId,
      device_id: params.deviceId,
    });

    const body = await response.json() as {
      status: string;
      pepper?: string;
      attempts_remaining?: number;
    };

    if (body.status === "wiped") {
      return { status: "wiped" };
    }

    if (body.status === "vault_expired") {
      return { status: "vault_expired" };
    }

    return {
      status: "allowed",
      pepper: fromBase64(body.pepper!),
      attemptsRemaining: body.attempts_remaining!,
    };
  }

  async reportUnsealFailure(params: UnsealFailureReport): Promise<void> {
    await this.post("/v1/vault/unseal-failed", {
      client_id: params.clientId,
      device_id: params.deviceId,
    });
  }

  async reportAuthSuccess(params: AuthSuccessReport): Promise<void> {
    await this.post("/v1/vault/auth-success", {
      client_id: params.clientId,
      device_id: params.deviceId,
    });
  }

  async deleteVaultRegistration(clientId: string, deviceId: string): Promise<void> {
    await this.post("/v1/vault/delete", {
      client_id: clientId,
      device_id: deviceId,
    });
  }

  private async post(path: string, body: Record<string, unknown>): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }

    return response;
  }
}

function fromBase64(str: string): Uint8Array {
  // Works in both Node.js (Buffer) and browser (atob)
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(str, "base64"));
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
