// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenInvalidator } from "../../src/client-registration/domain/port/outgoing/token-invalidator.js";
import type { ChallengeInvalidator } from "../../src/client-registration/domain/port/outgoing/challenge-invalidator.js";
import type { RotationProofVerifier } from "../../src/client-registration/domain/port/outgoing/rotation-proof-verifier.js";
import type { AdminAuthenticator } from "../../src/client-registration/domain/port/outgoing/admin-authenticator.js";
import type { RevokeClientRequest } from "../../src/client-registration/domain/port/incoming/revoke-client.js";
import type { RotateCommitmentRequest } from "../../src/client-registration/domain/port/incoming/rotate-commitment.js";
import type { Commitment } from "../../src/client-registration/domain/model/commitment.js";

/**
 * Test-only AdminAuthenticator that accepts all non-empty identities.
 * This is NOT the production StubAdminAuthenticator, so it passes the
 * fail-fast guard in createLifecycleService.
 */
export class TestAdminAuthenticator implements AdminAuthenticator {
  async isValidAdmin(adminIdentity: string): Promise<boolean> {
    return adminIdentity.length > 0;
  }
}

export function createCapturingTokenInvalidator(): TokenInvalidator & { invalidatedClients: string[] } {
  const invalidatedClients: string[] = [];
  return {
    invalidatedClients,
    invalidateAllForClient: async (clientIdentifier: string) => {
      invalidatedClients.push(clientIdentifier);
    },
  };
}

export function createCapturingChallengeInvalidator(): ChallengeInvalidator & { invalidatedClients: string[] } {
  const invalidatedClients: string[] = [];
  return {
    invalidatedClients,
    invalidateAllForClient: async (clientIdentifier: string) => {
      invalidatedClients.push(clientIdentifier);
    },
  };
}

export function createStubRotationProofVerifier(valid: boolean = true): RotationProofVerifier {
  return {
    verify: (
      _currentCommitment: Commitment,
      _currentProofBytes: Uint8Array,
      _newCommitment: Commitment,
      _newProofBytes: Uint8Array,
    ) => valid,
  };
}

export function validRevokeRequest(
  identifier: string = "test-client-1",
  adminIdentity: string = "admin-alice",
): RevokeClientRequest {
  return {
    clientIdentifier: identifier,
    adminIdentity,
  };
}

export function validRotateRequest(
  identifier: string = "test-client-1",
  newCommitmentByte: number = 0xcd,
): RotateCommitmentRequest {
  return {
    clientIdentifier: identifier,
    currentProofBytes: new Uint8Array(32).fill(1),
    newCommitmentBytes: new Uint8Array(32).fill(newCommitmentByte),
    newCommitmentProofBytes: new Uint8Array(32).fill(2),
  };
}
