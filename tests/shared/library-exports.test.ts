// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import {
  // Domain Models
  Client,
  ClientId,
  Commitment,
  EnrollmentReceipt,
  // Domain Events
  ClientEnrolled,
  ClientRevoked,
  CommitmentRotated,
  // Domain Services
  EnrollmentPolicy,
  RevocationPolicy,
  RotationPolicy,
  // Application Use Cases
  EnrollClientUseCase,
  RevokeClientUseCase,
  RotateCommitmentUseCase,
  // Shared Errors
  EnrollmentError,
  LifecycleError,
  // Factories
  createEnrollmentService,
  createLifecycleService,
  // Reference Adapters
  InMemoryClientRepository,
  StubCommitmentVerifier,
  StubProofOfPossessionVerifier,
  CryptoRandomIdGenerator,
  ConsoleAuditLogger,
  NoopEventPublisher,
  StubTokenInvalidator,
  StubChallengeInvalidator,
  StubRotationProofVerifier,
  // ZK Verification — Domain Models
  Proof,
  GroupElement,
  ScalarValue,
  DomainSeparationTag,
  Transcript,
  // ZK Verification — Domain Events
  ProofVerified,
  // ZK Verification — Domain Service
  ProofVerificationPolicy,
  ProofVerificationError,
  // ZK Verification — Application Use Case
  VerifyProofUseCase,
  // ZK Verification — Factory
  createVerificationService,
  // ZK Verification — Reference Adapters
  StubElementValidator,
  StubCommitmentLookup,
  StubChallengeConsumer,
  StubProofEquationVerifier,
  StubTranscriptHasher,
  StubFailedAttemptTracker,
  // API Access Control — Domain Models
  TokenId,
  Audience,
  AuthenticationLevel,
  STANDARD_TTL_MS,
  ELEVATED_TTL_MS,
  ttlForLevel,
  TokenClaims,
  AccessToken,
  // API Access Control — Domain Events
  TokenIssued,
  // API Access Control — Domain Services
  TokenIssuancePolicy,
  IssuancePolicyError,
  TokenValidationChain,
  ValidationError,
  // API Access Control — Application Use Cases
  IssueTokenUseCase,
  ValidateTokenUseCase,
  // API Access Control — Factory
  createAccessControlService,
  // API Access Control — Reference Adapters
  StubTokenSigner,
  StubTokenVerifier,
  StubAuthorizationChecker,
} from "../../src/index.js";

// Smoke test: verifies all public exports are accessible.
// Does not test functionality — that is covered by unit and acceptance tests.
describe("Library exports", () => {
  it("exports all domain models", () => {
    expect(Client).toBeDefined();
    expect(ClientId).toBeDefined();
    expect(Commitment).toBeDefined();
    expect(EnrollmentReceipt).toBeDefined();
  });

  it("exports domain events", () => {
    expect(ClientEnrolled).toBeDefined();
    expect(ClientRevoked).toBeDefined();
    expect(CommitmentRotated).toBeDefined();
  });

  it("exports domain services", () => {
    expect(EnrollmentPolicy).toBeDefined();
    expect(RevocationPolicy).toBeDefined();
    expect(RotationPolicy).toBeDefined();
  });

  it("exports application use cases", () => {
    expect(EnrollClientUseCase).toBeDefined();
    expect(RevokeClientUseCase).toBeDefined();
    expect(RotateCommitmentUseCase).toBeDefined();
  });

  it("exports shared errors", () => {
    expect(EnrollmentError).toBeDefined();
    expect(LifecycleError).toBeDefined();
  });

  it("exports factory functions", () => {
    expect(createEnrollmentService).toBeDefined();
    expect(typeof createEnrollmentService).toBe("function");
    expect(createLifecycleService).toBeDefined();
    expect(typeof createLifecycleService).toBe("function");
  });

  it("exports all reference adapters", () => {
    expect(InMemoryClientRepository).toBeDefined();
    expect(StubCommitmentVerifier).toBeDefined();
    expect(StubProofOfPossessionVerifier).toBeDefined();
    expect(CryptoRandomIdGenerator).toBeDefined();
    expect(ConsoleAuditLogger).toBeDefined();
    expect(NoopEventPublisher).toBeDefined();
    expect(StubTokenInvalidator).toBeDefined();
    expect(StubChallengeInvalidator).toBeDefined();
    expect(StubRotationProofVerifier).toBeDefined();
  });

  // ===== ZK Verification Bounded Context =====

  it("exports zk-verification domain models", () => {
    expect(Proof).toBeDefined();
    expect(GroupElement).toBeDefined();
    expect(ScalarValue).toBeDefined();
    expect(DomainSeparationTag).toBeDefined();
    expect(Transcript).toBeDefined();
  });

  it("exports zk-verification domain events", () => {
    expect(ProofVerified).toBeDefined();
  });

  it("exports zk-verification domain service", () => {
    expect(ProofVerificationPolicy).toBeDefined();
    expect(ProofVerificationError).toBeDefined();
  });

  it("exports zk-verification application use case", () => {
    expect(VerifyProofUseCase).toBeDefined();
  });

  it("exports zk-verification factory function", () => {
    expect(createVerificationService).toBeDefined();
    expect(typeof createVerificationService).toBe("function");
  });

  it("exports zk-verification reference adapters", () => {
    expect(StubElementValidator).toBeDefined();
    expect(StubCommitmentLookup).toBeDefined();
    expect(StubChallengeConsumer).toBeDefined();
    expect(StubProofEquationVerifier).toBeDefined();
    expect(StubTranscriptHasher).toBeDefined();
    expect(StubFailedAttemptTracker).toBeDefined();
  });

  // ===== API Access Control Bounded Context =====

  it("exports api-access-control domain models", () => {
    expect(TokenId).toBeDefined();
    expect(Audience).toBeDefined();
    expect(AuthenticationLevel).toBeDefined();
    expect(STANDARD_TTL_MS).toBe(15 * 60 * 1000);
    expect(ELEVATED_TTL_MS).toBe(5 * 60 * 1000);
    expect(ttlForLevel).toBeDefined();
    expect(TokenClaims).toBeDefined();
    expect(AccessToken).toBeDefined();
  });

  it("exports api-access-control domain events", () => {
    expect(TokenIssued).toBeDefined();
  });

  it("exports api-access-control domain services", () => {
    expect(TokenIssuancePolicy).toBeDefined();
    expect(IssuancePolicyError).toBeDefined();
    expect(TokenValidationChain).toBeDefined();
    expect(ValidationError).toBeDefined();
  });

  it("exports api-access-control application use cases", () => {
    expect(IssueTokenUseCase).toBeDefined();
    expect(ValidateTokenUseCase).toBeDefined();
  });

  it("exports api-access-control factory function", () => {
    expect(createAccessControlService).toBeDefined();
    expect(typeof createAccessControlService).toBe("function");
  });

  it("exports api-access-control reference adapters", () => {
    expect(StubTokenSigner).toBeDefined();
    expect(StubTokenVerifier).toBeDefined();
    expect(StubAuthorizationChecker).toBeDefined();
  });
});
