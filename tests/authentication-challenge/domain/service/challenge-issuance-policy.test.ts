// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ChallengeIssuancePolicy, ChallengeIssuanceError } from "../../../../src/authentication-challenge/domain/service/challenge-issuance-policy.js";
import { ProtocolVersion } from "../../../../src/authentication-challenge/domain/model/protocol-version.js";

describe("ChallengeIssuancePolicy", () => {
  const supportedVersions = [ProtocolVersion.fromString("1.0")];
  const policy = new ChallengeIssuancePolicy(supportedVersions, false);

  it("should return null when all preconditions are met", () => {
    const result = policy.validate({
      credentialValid: true,
      clientStatus: "active",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeNull();
  });

  it("should return INVALID_CREDENTIAL when credential is invalid", () => {
    const result = policy.validate({
      credentialValid: false,
      clientStatus: "active",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("INVALID_CREDENTIAL");
    expect(result!.message).toBe("Invalid credential");
  });

  it("should return CLIENT_REVOKED when client status is revoked", () => {
    const result = policy.validate({
      credentialValid: true,
      clientStatus: "revoked",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("CLIENT_REVOKED");
    expect(result!.message).toBe("Client has been revoked");
  });

  it("should return CLIENT_UNKNOWN when client status is unknown", () => {
    const result = policy.validate({
      credentialValid: false,
      clientStatus: "unknown",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("CLIENT_UNKNOWN");
    expect(result!.message).toBe("Client not found");
  });

  it("should return CLIENT_LOCKED_OUT when client is locked out", () => {
    const result = policy.validate({
      credentialValid: true,
      clientStatus: "active",
      isLockedOut: true,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("CLIENT_LOCKED_OUT");
    expect(result!.message).toBe("Client is temporarily locked out");
  });

  it("should return UNSUPPORTED_VERSION when version is not supported", () => {
    const result = policy.validate({
      credentialValid: true,
      clientStatus: "active",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("0.1-deprecated"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("UNSUPPORTED_VERSION");
    expect(result!.message).toContain("0.1-deprecated");
    expect(result!.supportedVersions).toEqual(["1.0"]);
  });

  it("should allow legacy API key when migration is active", () => {
    const policyWithMigration = new ChallengeIssuancePolicy(supportedVersions, true);

    const result = policyWithMigration.validate({
      credentialValid: true,
      clientStatus: "active",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: true,
    });

    expect(result).toBeNull();
  });

  it("should refuse legacy API key when migration period is over", () => {
    const policyNoMigration = new ChallengeIssuancePolicy(supportedVersions, false);

    const result = policyNoMigration.validate({
      credentialValid: true,
      clientStatus: "active",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: true,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("LEGACY_NOT_ALLOWED");
    expect(result!.message).toContain("no longer accepted");
  });

  it("should check lockout BEFORE credential validity (NIST SP 800-63B)", () => {
    // When both lockout and invalid credential, lockout should take precedence
    const result = policy.validate({
      credentialValid: false,
      clientStatus: "active",
      isLockedOut: true,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("CLIENT_LOCKED_OUT");
  });

  it("should return CLIENT_SUSPENDED when client status is suspended (BC10)", () => {
    const result = policy.validate({
      credentialValid: true,
      clientStatus: "suspended",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("CLIENT_SUSPENDED");
    expect(result!.message).toBe("Client is suspended");
  });

  it("should check suspended status before lockout check (BC10)", () => {
    const result = policy.validate({
      credentialValid: true,
      clientStatus: "suspended",
      isLockedOut: true,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeInstanceOf(ChallengeIssuanceError);
    expect(result!.code).toBe("CLIENT_SUSPENDED");
  });

  it("should accept any of multiple supported versions (some, not every)", () => {
    const multiVersionPolicy = new ChallengeIssuancePolicy(
      [ProtocolVersion.fromString("1.0"), ProtocolVersion.fromString("2.0")],
      false,
    );

    // Version "1.0" should be accepted even though "2.0" also exists
    const result = multiVersionPolicy.validate({
      credentialValid: true,
      clientStatus: "active",
      isLockedOut: false,
      requestedVersion: ProtocolVersion.fromString("1.0"),
      isLegacyApiKey: false,
    });

    expect(result).toBeNull();
  });
});
