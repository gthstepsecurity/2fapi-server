// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { IssueTokenUseCase } from "../../src/api-access-control/application/usecase/issue-token.usecase.js";
import { TokenIssuancePolicy } from "../../src/api-access-control/domain/service/token-issuance-policy.js";
import type { VerificationReceiptStore } from "../../src/api-access-control/domain/port/outgoing/verification-receipt-store.js";
import { InMemoryVerificationReceiptStore } from "../../src/api-access-control/infrastructure/adapter/outgoing/in-memory-verification-receipt-store.js";
import {
  createAllStubs,
  validIssueTokenRequest,
  ISSUER,
} from "../helpers/access-control-test-helpers.js";

const NOW_MS = 1000000;

function createUseCase(receiptStore: VerificationReceiptStore) {
  const stubs = createAllStubs({ clock: { nowMs: () => NOW_MS } });
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
  return { useCase, stubs };
}

describe("FIX 2 — Verification Receipt Binding (Enhanced)", () => {
  describe("IssueTokenUseCase with required receipt store", () => {
    it("refuses token issuance without receiptId", async () => {
      const store = new InMemoryVerificationReceiptStore();
      const { useCase, stubs } = createUseCase(store);

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

    it("issues token with valid receiptId", async () => {
      const store = new InMemoryVerificationReceiptStore();
      await store.store("receipt-valid-001", "alice-payment-service");

      const { useCase } = createUseCase(store);

      const response = await useCase.execute({
        ...validIssueTokenRequest(),
        verificationReceiptId: "receipt-valid-001",
      });

      expect(response.success).toBe(true);
    });

    it("refuses token with already-consumed receiptId", async () => {
      const store = new InMemoryVerificationReceiptStore();
      await store.store("receipt-one-time", "alice-payment-service");

      const { useCase, stubs } = createUseCase(store);

      // First use — succeeds
      const first = await useCase.execute({
        ...validIssueTokenRequest(),
        verificationReceiptId: "receipt-one-time",
      });
      expect(first.success).toBe(true);

      // Second use — refused
      const second = await useCase.execute({
        ...validIssueTokenRequest(),
        verificationReceiptId: "receipt-one-time",
      });
      expect(second.success).toBe(false);
      if (!second.success) {
        expect(second.error).toBe("issuance_refused");
      }
      expect(
        stubs.auditLogger.entries.some(
          (e) => e.details.reason === "invalid_verification_receipt",
        ),
      ).toBe(true);
    });

    it("refuses token with receiptId for different client", async () => {
      const store = new InMemoryVerificationReceiptStore();
      await store.store("receipt-alice-123", "alice-payment-service");

      const { useCase, stubs } = createUseCase(store);

      // Bob tries to use Alice's receipt
      const response = await useCase.execute({
        ...validIssueTokenRequest({ clientIdentifier: "bob-payment-service" }),
        verificationReceiptId: "receipt-alice-123",
      });

      expect(response.success).toBe(false);
      if (!response.success) {
        expect(response.error).toBe("issuance_refused");
      }
      expect(
        stubs.auditLogger.entries.some(
          (e) => e.details.reason === "receipt_client_mismatch",
        ),
      ).toBe(true);
    });
  });

  describe("InMemoryVerificationReceiptStore", () => {
    it("stores and consumes a receipt returning clientIdentifier", async () => {
      const store = new InMemoryVerificationReceiptStore();
      await store.store("r-001", "alice");

      const result = await store.consume("r-001");
      expect(result).toBe("alice");
    });

    it("returns null when consuming non-existent receipt", async () => {
      const store = new InMemoryVerificationReceiptStore();

      const result = await store.consume("r-unknown");
      expect(result).toBeNull();
    });

    it("returns null on second consumption (one-time use)", async () => {
      const store = new InMemoryVerificationReceiptStore();
      await store.store("r-001", "alice");

      await store.consume("r-001");
      const second = await store.consume("r-001");
      expect(second).toBeNull();
    });
  });
});
