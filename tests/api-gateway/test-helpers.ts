// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Shared test helpers for API Gateway tests.
 * Provides stub use cases and server factory for inject()-based testing.
 */
import type { FastifyInstance } from "fastify";
import type { EnrollClient, EnrollClientRequest, EnrollClientResponse } from "../../src/client-registration/domain/port/incoming/enroll-client.js";
import type { RequestChallenge, RequestChallengeRequest, RequestChallengeResponse } from "../../src/authentication-challenge/domain/port/incoming/request-challenge.js";
import type { VerifyProof, VerifyProofRequest, VerifyProofResponse } from "../../src/zk-verification/domain/port/incoming/verify-proof.js";
import type { IssueToken, IssueTokenRequest, IssueTokenResponse } from "../../src/api-access-control/domain/port/incoming/issue-token.js";
import type { ValidateToken, ValidateTokenRequest, ValidateTokenResponse } from "../../src/api-access-control/domain/port/incoming/validate-token.js";
import type { RevokeClient, RevokeClientRequest, RevokeClientResponse } from "../../src/client-registration/domain/port/incoming/revoke-client.js";
import type { RotateCommitment, RotateCommitmentRequest, RotateCommitmentResponse } from "../../src/client-registration/domain/port/incoming/rotate-commitment.js";
import { createDevelopmentServer, type ApiGatewayDependencies } from "../../src/api-gateway/server.js";

// --- Stub Use Cases ---

export class StubEnrollClient implements EnrollClient {
  private _response: EnrollClientResponse = {
    success: true,
    referenceId: "ref-123",
    clientIdentifier: "test-client",
  };
  lastRequest: EnrollClientRequest | null = null;

  setResponse(response: EnrollClientResponse): void {
    this._response = response;
  }

  async execute(request: EnrollClientRequest): Promise<EnrollClientResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

export class StubRequestChallenge implements RequestChallenge {
  private _response: RequestChallengeResponse = {
    success: true,
    challengeId: "ch-42",
    nonce: new Uint8Array(32).fill(1),
    channelBinding: new Uint8Array(32).fill(2),
    expiresAtMs: Date.now() + 120_000,
    protocolVersion: "1.0",
    legacyFirstFactor: false,
  };
  lastRequest: RequestChallengeRequest | null = null;

  setResponse(response: RequestChallengeResponse): void {
    this._response = response;
  }

  async execute(request: RequestChallengeRequest): Promise<RequestChallengeResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

export class StubVerifyProof implements VerifyProof {
  private _response: VerifyProofResponse = {
    success: true,
    clientIdentifier: "test-client",
  };
  lastRequest: VerifyProofRequest | null = null;

  setResponse(response: VerifyProofResponse): void {
    this._response = response;
  }

  async execute(request: VerifyProofRequest): Promise<VerifyProofResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

export class StubIssueToken implements IssueToken {
  private _response: IssueTokenResponse = {
    success: true,
    bearerToken: "token-abc-123",
    expiresAtMs: Date.now() + 900_000,
  };
  lastRequest: IssueTokenRequest | null = null;

  setResponse(response: IssueTokenResponse): void {
    this._response = response;
  }

  async execute(request: IssueTokenRequest): Promise<IssueTokenResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

export class StubValidateToken implements ValidateToken {
  private _response: ValidateTokenResponse = {
    success: true,
    clientIdentifier: "test-client",
    audience: "test-resource",
    level: "standard",
  };
  lastRequest: ValidateTokenRequest | null = null;

  setResponse(response: ValidateTokenResponse): void {
    this._response = response;
  }

  async execute(request: ValidateTokenRequest): Promise<ValidateTokenResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

export class StubRevokeClient implements RevokeClient {
  private _response: RevokeClientResponse = { success: true };
  lastRequest: RevokeClientRequest | null = null;

  setResponse(response: RevokeClientResponse): void {
    this._response = response;
  }

  async execute(request: RevokeClientRequest): Promise<RevokeClientResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

export class StubRotateCommitment implements RotateCommitment {
  private _response: RotateCommitmentResponse = { success: true };
  lastRequest: RotateCommitmentRequest | null = null;

  setResponse(response: RotateCommitmentResponse): void {
    this._response = response;
  }

  async execute(request: RotateCommitmentRequest): Promise<RotateCommitmentResponse> {
    this.lastRequest = request;
    return this._response;
  }
}

// --- Test App Factory ---

export interface TestDeps {
  enrollClient: StubEnrollClient;
  requestChallenge: StubRequestChallenge;
  verifyProof: StubVerifyProof;
  issueToken: StubIssueToken;
  validateToken: StubValidateToken;
  revokeClient: StubRevokeClient;
  rotateCommitment: StubRotateCommitment;
}

export function createTestDeps(): TestDeps {
  return {
    enrollClient: new StubEnrollClient(),
    requestChallenge: new StubRequestChallenge(),
    verifyProof: new StubVerifyProof(),
    issueToken: new StubIssueToken(),
    validateToken: new StubValidateToken(),
    revokeClient: new StubRevokeClient(),
    rotateCommitment: new StubRotateCommitment(),
  };
}

export function createTestApp(deps?: Partial<TestDeps>): {
  app: FastifyInstance;
  deps: TestDeps;
} {
  const testDeps = { ...createTestDeps(), ...deps };
  const app = createDevelopmentServer(testDeps, { serviceAudience: "test-service" });
  return { app, deps: testDeps };
}

// --- Valid payloads ---

export function validBase64(length = 32): string {
  return Buffer.from(new Uint8Array(length).fill(42)).toString("base64");
}

export function validProofBase64(): string {
  // 96 bytes = announcement(32) + responseS(32) + responseR(32)
  return Buffer.from(new Uint8Array(96).fill(42)).toString("base64");
}
