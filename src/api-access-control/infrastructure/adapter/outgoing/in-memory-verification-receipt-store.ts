// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { VerificationReceiptStore } from "../../../domain/port/outgoing/verification-receipt-store.js";

/**
 * In-memory implementation of VerificationReceiptStore.
 * Stores receipts as a Map from receiptId to clientIdentifier.
 * Each receipt can only be consumed once (one-time use).
 */
export class InMemoryVerificationReceiptStore implements VerificationReceiptStore {
  private readonly receipts = new Map<string, string>();

  async store(receiptId: string, clientIdentifier: string): Promise<void> {
    this.receipts.set(receiptId, clientIdentifier);
  }

  async consume(receiptId: string): Promise<string | null> {
    const clientIdentifier = this.receipts.get(receiptId);
    if (clientIdentifier === undefined) {
      return null;
    }
    this.receipts.delete(receiptId);
    return clientIdentifier;
  }
}
