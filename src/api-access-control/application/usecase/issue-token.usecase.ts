// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  IssueToken,
  IssueTokenRequest,
  IssueTokenResponse,
} from "../../domain/port/incoming/issue-token.js";
import type { ClientStatusChecker } from "../../domain/port/outgoing/client-status-checker.js";
import type { AuthorizationChecker } from "../../domain/port/outgoing/authorization-checker.js";
import type { TokenSigner } from "../../domain/port/outgoing/token-signer.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { VerificationReceiptStore } from "../../domain/port/outgoing/verification-receipt-store.js";
import { TokenIssuancePolicy } from "../../domain/service/token-issuance-policy.js";
import { TokenClaims } from "../../domain/model/token-claims.js";
import { TokenId } from "../../domain/model/token-id.js";
import { Audience } from "../../domain/model/audience.js";
import { AccessToken } from "../../domain/model/access-token.js";
import {
  AuthenticationLevel,
  ttlForLevel,
} from "../../domain/model/authentication-level.js";
import { TokenIssued } from "../../domain/event/token-issued.js";

const MAX_CLIENT_IDENTIFIER_BYTES = 256;

export class IssueTokenUseCase implements IssueToken {
  constructor(
    private readonly clientStatusChecker: ClientStatusChecker,
    private readonly authorizationChecker: AuthorizationChecker,
    private readonly tokenSigner: TokenSigner,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
    private readonly clock: Clock,
    private readonly idGenerator: IdGenerator,
    private readonly policy: TokenIssuancePolicy,
    private readonly issuer: string,
    private readonly receiptStore: VerificationReceiptStore,
  ) {}

  async execute(request: IssueTokenRequest): Promise<IssueTokenResponse> {
    // Input validation
    const identifierByteLength = new TextEncoder().encode(request.clientIdentifier).length;
    if (identifierByteLength === 0 || identifierByteLength > MAX_CLIENT_IDENTIFIER_BYTES) {
      await this.auditRefused(request.clientIdentifier, "invalid_client_identifier");
      return { success: false, error: "issuance_refused" };
    }

    if (request.audience.length === 0) {
      await this.auditRefused(request.clientIdentifier, "invalid_audience");
      return { success: false, error: "issuance_refused" };
    }

    if (request.channelBindingHash.length === 0) {
      await this.auditRefused(request.clientIdentifier, "invalid_channel_binding_hash");
      return { success: false, error: "issuance_refused" };
    }

    // Verification receipt binding: require a valid one-time receipt
    if (!request.verificationReceiptId || request.verificationReceiptId.length === 0) {
      await this.auditRefused(request.clientIdentifier, "missing_verification_receipt");
      return { success: false, error: "issuance_refused" };
    }

    const receiptClientIdentifier = await this.receiptStore.consume(request.verificationReceiptId);
    if (receiptClientIdentifier === null) {
      await this.auditRefused(request.clientIdentifier, "invalid_verification_receipt");
      return { success: false, error: "issuance_refused" };
    }

    // Verify the receipt belongs to the requesting client
    if (receiptClientIdentifier !== request.clientIdentifier) {
      await this.auditRefused(request.clientIdentifier, "receipt_client_mismatch");
      return { success: false, error: "issuance_refused" };
    }

    // Check client status and authorization
    const clientActive = await this.clientStatusChecker.isActive(request.clientIdentifier);
    const clientAuthorized = await this.authorizationChecker.isAuthorized(
      request.clientIdentifier,
      request.audience,
    );

    // Policy validation
    const policyError = this.policy.validate({ clientActive, clientAuthorized });
    if (policyError !== null) {
      await this.auditRefused(request.clientIdentifier, policyError.code);
      return { success: false, error: "issuance_refused" };
    }

    // Build token
    const nowMs = this.clock.nowMs();
    const level = request.authenticationLevel ?? AuthenticationLevel.STANDARD;
    const ttlMs = ttlForLevel(level);
    const expiresAtMs = nowMs + ttlMs;
    const tokenId = TokenId.fromString(this.idGenerator.generate());

    let audience: Audience;
    try {
      audience = Audience.fromString(request.audience);
    } catch {
      await this.auditRefused(request.clientIdentifier, "invalid_audience");
      return { success: false, error: "issuance_refused" };
    }

    const claims = TokenClaims.create({
      iss: this.issuer,
      sub: request.clientIdentifier,
      aud: audience,
      exp: expiresAtMs,
      iat: nowMs,
      jti: tokenId,
      cnf: request.channelBindingHash,
      level,
    });

    // Sign
    const payload = new TextEncoder().encode(claims.serialize());
    const signedBytes = await this.tokenSigner.sign(payload);
    const token = AccessToken.issue(claims, signedBytes);

    // Audit
    await this.auditLogger.log({
      action: "token_issued",
      clientIdentifier: request.clientIdentifier,
      timestamp: new Date(),
      details: {
        tokenId: tokenId.toString(),
        audience: request.audience,
        level,
        expiresAtMs,
      },
    });

    // Event
    await this.eventPublisher.publish(
      new TokenIssued(
        request.clientIdentifier,
        request.audience,
        level,
        tokenId.toString(),
        nowMs,
      ),
    );

    return {
      success: true,
      bearerToken: token.toBearer(),
      expiresAtMs,
    };
  }

  private async auditRefused(clientIdentifier: string, reason: string): Promise<void> {
    await this.auditLogger.log({
      action: "issuance_refused",
      clientIdentifier,
      timestamp: new Date(),
      details: { reason },
    });
  }
}
