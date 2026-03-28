// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuditLogger, AuditEntry } from "../../src/api-access-control/domain/port/outgoing/audit-logger.js";
import type { EventPublisher, DomainEvent } from "../../src/api-access-control/domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../src/api-access-control/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../src/api-access-control/domain/port/outgoing/id-generator.js";
import type { VerificationReceiptStore } from "../../src/api-access-control/domain/port/outgoing/verification-receipt-store.js";
import type { IssueTokenRequest } from "../../src/api-access-control/domain/port/incoming/issue-token.js";
import type { ValidateTokenRequest } from "../../src/api-access-control/domain/port/incoming/validate-token.js";
import { StubTokenSigner } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-token-signer.js";
import { StubTokenVerifier } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-token-verifier.js";
import { StubClientStatusChecker } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-client-status-checker.js";
import { StubAuthorizationChecker } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-authorization-checker.js";
import { InMemoryVerificationReceiptStore } from "../../src/api-access-control/infrastructure/adapter/outgoing/in-memory-verification-receipt-store.js";

export { StubTokenSigner } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-token-signer.js";
export { StubTokenVerifier } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-token-verifier.js";
export { StubClientStatusChecker } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-client-status-checker.js";
export { StubAuthorizationChecker } from "../../src/api-access-control/infrastructure/adapter/outgoing/stub-authorization-checker.js";
export { InMemoryVerificationReceiptStore } from "../../src/api-access-control/infrastructure/adapter/outgoing/in-memory-verification-receipt-store.js";

// --- Factory functions ---

export function createCapturingAuditLogger(): AuditLogger & { entries: AuditEntry[] } {
  const logger = {
    entries: [] as AuditEntry[],
    async log(entry: AuditEntry): Promise<void> {
      logger.entries.push(entry);
    },
  };
  return logger;
}

export function createCapturingEventPublisher(): EventPublisher & { events: DomainEvent[] } {
  const publisher = {
    events: [] as DomainEvent[],
    async publish(event: DomainEvent): Promise<void> {
      publisher.events.push(event);
    },
  };
  return publisher;
}

export function createStubClock(nowMs = 1000000): Clock {
  return { nowMs: () => nowMs };
}

export function createStubIdGenerator(prefix = "tok"): IdGenerator {
  let counter = 0;
  return {
    generate(): string {
      counter++;
      return `${prefix}-${String(counter).padStart(3, "0")}`;
    },
  };
}

export const ISSUER = "2fapi-server";
export const CHANNEL_BINDING_HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
export const DEFAULT_RECEIPT_ID = "test-receipt-001";

export function validIssueTokenRequest(
  overrides: Partial<IssueTokenRequest> = {},
): IssueTokenRequest {
  return {
    clientIdentifier: overrides.clientIdentifier ?? "alice-payment-service",
    audience: overrides.audience ?? "payment-service",
    channelBindingHash: overrides.channelBindingHash ?? CHANNEL_BINDING_HASH,
    authenticationLevel: overrides.authenticationLevel,
    verificationReceiptId: overrides.verificationReceiptId ?? DEFAULT_RECEIPT_ID,
  };
}

/**
 * Creates a receipt store pre-loaded with a receipt for the default test client.
 * Use this when tests need a simple happy-path receipt store.
 */
export function createPreloadedReceiptStore(
  clientIdentifier = "alice-payment-service",
  receiptId = DEFAULT_RECEIPT_ID,
): InMemoryVerificationReceiptStore {
  const store = new InMemoryVerificationReceiptStore();
  // Synchronously call store — InMemoryVerificationReceiptStore resolves immediately
  void store.store(receiptId, clientIdentifier);
  return store;
}

/**
 * A permissive receipt store for testing that accepts any non-empty receiptId.
 * It tracks which receiptIds have been consumed to test one-time-use semantics.
 * When a receipt has not been explicitly stored, it returns a "wildcard" client
 * identifier that matches whatever the caller expects. This is done by deferring
 * client identity resolution to the test setup.
 *
 * For tests focused on receipt binding itself, use InMemoryVerificationReceiptStore directly.
 */
export class AutoReceiptStore implements VerificationReceiptStore {
  private readonly receipts = new Map<string, string>();
  private readonly consumed = new Set<string>();

  constructor() {
    // Pre-load default receipt for the default test client
    this.receipts.set(DEFAULT_RECEIPT_ID, "alice-payment-service");
  }

  async store(receiptId: string, clientIdentifier: string): Promise<void> {
    this.receipts.set(receiptId, clientIdentifier);
  }

  async consume(receiptId: string): Promise<string | null> {
    if (this.consumed.has(receiptId)) return null;
    const clientIdentifier = this.receipts.get(receiptId);
    if (clientIdentifier !== undefined) {
      this.consumed.add(receiptId);
      this.receipts.delete(receiptId);
      return clientIdentifier;
    }
    return null;
  }

  /**
   * Preloads a receipt for a specific client.
   */
  preload(receiptId: string, clientIdentifier: string): void {
    this.receipts.set(receiptId, clientIdentifier);
    this.consumed.delete(receiptId);
  }
}

export function validValidateTokenRequest(
  overrides: Partial<ValidateTokenRequest> = {},
): ValidateTokenRequest {
  return {
    bearerToken: overrides.bearerToken ?? "dummy-bearer-token",
    channelBindingHash: overrides.channelBindingHash ?? CHANNEL_BINDING_HASH,
    expectedAudience: overrides.expectedAudience ?? "payment-service",
  };
}

export interface AllStubs {
  tokenSigner: StubTokenSigner;
  tokenVerifier: StubTokenVerifier;
  clientStatusChecker: StubClientStatusChecker;
  authorizationChecker: StubAuthorizationChecker;
  auditLogger: ReturnType<typeof createCapturingAuditLogger>;
  eventPublisher: ReturnType<typeof createCapturingEventPublisher>;
  clock: Clock;
  idGenerator: IdGenerator;
  receiptStore: AutoReceiptStore;
}

/**
 * Creates a full set of stubs configured for a happy-path scenario.
 */
export function createAllStubs(overrides: Partial<AllStubs> = {}): AllStubs {
  return {
    tokenSigner: overrides.tokenSigner ?? new StubTokenSigner(),
    tokenVerifier: overrides.tokenVerifier ?? new StubTokenVerifier(),
    clientStatusChecker: overrides.clientStatusChecker ?? new StubClientStatusChecker(true),
    authorizationChecker: overrides.authorizationChecker ?? new StubAuthorizationChecker(true),
    auditLogger: overrides.auditLogger ?? createCapturingAuditLogger(),
    eventPublisher: overrides.eventPublisher ?? createCapturingEventPublisher(),
    clock: overrides.clock ?? createStubClock(),
    idGenerator: overrides.idGenerator ?? createStubIdGenerator(),
    receiptStore: overrides.receiptStore ?? new AutoReceiptStore(),
  };
}
