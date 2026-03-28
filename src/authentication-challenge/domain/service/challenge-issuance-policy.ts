// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { ProtocolVersion } from "../model/protocol-version.js";

export type ChallengeIssuanceErrorCode =
  | "INVALID_CREDENTIAL"
  | "CLIENT_REVOKED"
  | "CLIENT_SUSPENDED"
  | "CLIENT_UNKNOWN"
  | "CLIENT_LOCKED_OUT"
  | "UNSUPPORTED_VERSION"
  | "LEGACY_NOT_ALLOWED";

export class ChallengeIssuanceError extends Error {
  constructor(
    readonly code: ChallengeIssuanceErrorCode,
    message: string,
    readonly supportedVersions?: readonly string[],
  ) {
    super(message);
  }
}

export interface IssuancePreconditions {
  readonly credentialValid: boolean;
  readonly clientStatus: "active" | "suspended" | "revoked" | "unknown";
  readonly isLockedOut: boolean;
  readonly requestedVersion: ProtocolVersion;
  readonly isLegacyApiKey: boolean;
}

export class ChallengeIssuancePolicy {
  constructor(
    private readonly supportedVersions: readonly ProtocolVersion[],
    private readonly legacyMigrationActive: boolean,
  ) {}

  validate(preconditions: IssuancePreconditions): ChallengeIssuanceError | null {
    if (preconditions.clientStatus === "unknown") {
      return new ChallengeIssuanceError("CLIENT_UNKNOWN", "Client not found");
    }

    if (preconditions.clientStatus === "revoked") {
      return new ChallengeIssuanceError("CLIENT_REVOKED", "Client has been revoked");
    }

    if (preconditions.clientStatus === "suspended") {
      return new ChallengeIssuanceError("CLIENT_SUSPENDED", "Client is suspended");
    }

    // Check lockout BEFORE credential validity per NIST SP 800-63B:
    // A locked-out account must be rejected regardless of credential validity
    // to prevent brute-force attacks during lockout period.
    if (preconditions.isLockedOut) {
      return new ChallengeIssuanceError("CLIENT_LOCKED_OUT", "Client is temporarily locked out");
    }

    if (!preconditions.credentialValid) {
      return new ChallengeIssuanceError("INVALID_CREDENTIAL", "Invalid credential");
    }

    if (preconditions.isLegacyApiKey && !this.legacyMigrationActive) {
      return new ChallengeIssuanceError("LEGACY_NOT_ALLOWED", "Legacy API key authentication is no longer accepted");
    }

    const isVersionSupported = this.supportedVersions.some(
      (v) => v.equals(preconditions.requestedVersion),
    );
    if (!isVersionSupported) {
      return new ChallengeIssuanceError(
        "UNSUPPORTED_VERSION",
        `Protocol version ${preconditions.requestedVersion.value} is not supported`,
        this.supportedVersions.map((v) => v.value),
      );
    }

    return null;
  }
}
