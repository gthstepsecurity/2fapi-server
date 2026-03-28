// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { IssueToken } from "./api-access-control/domain/port/incoming/issue-token.js";
import type { ValidateToken } from "./api-access-control/domain/port/incoming/validate-token.js";
import type { TokenSigner } from "./api-access-control/domain/port/outgoing/token-signer.js";
import type { TokenVerifier } from "./api-access-control/domain/port/outgoing/token-verifier.js";
import type { ClientStatusChecker } from "./api-access-control/domain/port/outgoing/client-status-checker.js";
import type { AuthorizationChecker } from "./api-access-control/domain/port/outgoing/authorization-checker.js";
import type { AuditLogger } from "./api-access-control/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./api-access-control/domain/port/outgoing/event-publisher.js";
import type { Clock } from "./api-access-control/domain/port/outgoing/clock.js";
import type { IdGenerator } from "./api-access-control/domain/port/outgoing/id-generator.js";
import type { VerificationReceiptStore } from "./api-access-control/domain/port/outgoing/verification-receipt-store.js";
import { IssueTokenUseCase } from "./api-access-control/application/usecase/issue-token.usecase.js";
import { ValidateTokenUseCase } from "./api-access-control/application/usecase/validate-token.usecase.js";
import { TokenIssuancePolicy } from "./api-access-control/domain/service/token-issuance-policy.js";
import { TokenValidationChain } from "./api-access-control/domain/service/token-validation-chain.js";

export interface AccessControlServiceDependencies {
  readonly tokenSigner: TokenSigner;
  readonly tokenVerifier: TokenVerifier;
  readonly clientStatusChecker: ClientStatusChecker;
  readonly authorizationChecker: AuthorizationChecker;
  readonly auditLogger: AuditLogger;
  readonly eventPublisher: EventPublisher;
  readonly clock: Clock;
  readonly idGenerator: IdGenerator;
  readonly receiptStore: VerificationReceiptStore;
  readonly issuer?: string;
}

export interface AccessControlService {
  readonly issueToken: IssueToken;
  readonly validateToken: ValidateToken;
}

export function createAccessControlService(
  deps: AccessControlServiceDependencies,
): AccessControlService {
  const issuancePolicy = new TokenIssuancePolicy();
  const validationChain = new TokenValidationChain();
  const issuer = deps.issuer ?? "2fapi-server";

  const issueToken = new IssueTokenUseCase(
    deps.clientStatusChecker,
    deps.authorizationChecker,
    deps.tokenSigner,
    deps.auditLogger,
    deps.eventPublisher,
    deps.clock,
    deps.idGenerator,
    issuancePolicy,
    issuer,
    deps.receiptStore,
  );

  const validateToken = new ValidateTokenUseCase(
    deps.tokenVerifier,
    deps.clientStatusChecker,
    deps.auditLogger,
    deps.clock,
    validationChain,
  );

  return { issueToken, validateToken };
}
