// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { IssueTokenUseCase } from "../../src/api-access-control/application/usecase/issue-token.usecase.js";
import { TokenIssuancePolicy } from "../../src/api-access-control/domain/service/token-issuance-policy.js";
import { InMemoryVerificationReceiptStore } from "../../src/api-access-control/infrastructure/adapter/outgoing/in-memory-verification-receipt-store.js";
import {
  createAllStubs,
  validIssueTokenRequest,
  ISSUER,
} from "../helpers/access-control-test-helpers.js";

const NOW_MS = 1000000;

function createUseCase(overrides: {
  receiptStore?: InMemoryVerificationReceiptStore;
} = {}) {
  const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
  const receiptStore = overrides.receiptStore ?? new InMemoryVerificationReceiptStore();
  const policy = new TokenIssuancePolicy();
  const useCase = new IssueTokenUseCase(
    stubs.clientStatusChecker,
    stubs.authorizationChecker,
    stubs.tokenSigner,
    stubs.auditLogger,
    stubs.eventPublisher,
    stubs.clock,
    stubs.idGenerator,
    policy,
    ISSUER,
    receiptStore,
  );
  return { useCase, stubs, receiptStore };
}

describe("FIX 5 — IssueToken Verification Receipt Binding", () => {
  it("issues token with a valid verification receipt", async () => {
    const receiptStore = new InMemoryVerificationReceiptStore();
    await receiptStore.store("receipt-valid-001", "alice-payment-service");

    const { useCase } = createUseCase({ receiptStore });

    const response = await useCase.execute({
      ...validIssueTokenRequest(),
      verificationReceiptId: "receipt-valid-001",
    });

    expect(response.success).toBe(true);
    // Receipt should be consumed (one-time use)
    const secondConsume = await receiptStore.consume("receipt-valid-001");
    expect(secondConsume).toBeNull();
  });

  it("refuses issuance without verification receipt", async () => {
    const { useCase, stubs } = createUseCase();

    const response = await useCase.execute({
      ...validIssueTokenRequest(),
      verificationReceiptId: undefined,
    });

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("issuance_refused");
    }
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("missing_verification_receipt");
  });

  it("refuses issuance with empty verification receipt", async () => {
    const { useCase, stubs } = createUseCase();

    const response = await useCase.execute({
      ...validIssueTokenRequest(),
      verificationReceiptId: "",
    });

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("issuance_refused");
    }
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("missing_verification_receipt");
  });

  it("refuses issuance with already-used (consumed) receipt", async () => {
    const receiptStore = new InMemoryVerificationReceiptStore();
    await receiptStore.store("receipt-one-time", "alice-payment-service");

    const { useCase, stubs } = createUseCase({ receiptStore });

    // First use — succeeds
    const first = await useCase.execute({
      ...validIssueTokenRequest(),
      verificationReceiptId: "receipt-one-time",
    });
    expect(first.success).toBe(true);

    // Second use — refused (receipt already consumed)
    const second = await useCase.execute({
      ...validIssueTokenRequest(),
      verificationReceiptId: "receipt-one-time",
    });
    expect(second.success).toBe(false);
    if (!second.success) {
      expect(second.error).toBe("issuance_refused");
    }
    expect(stubs.auditLogger.entries.some(
      (e) => e.details.reason === "invalid_verification_receipt"
    )).toBe(true);
  });

  it("refuses issuance with unknown receipt", async () => {
    const receiptStore = new InMemoryVerificationReceiptStore();
    const { useCase, stubs } = createUseCase({ receiptStore });

    const response = await useCase.execute({
      ...validIssueTokenRequest(),
      verificationReceiptId: "receipt-unknown",
    });

    expect(response.success).toBe(false);
    if (!response.success) {
      expect(response.error).toBe("issuance_refused");
    }
    expect(stubs.auditLogger.entries[0]!.details.reason).toBe("invalid_verification_receipt");
  });
});
