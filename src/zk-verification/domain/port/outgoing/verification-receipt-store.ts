// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Outgoing port for storing verification receipts.
 * On successful proof verification, a receipt is generated and stored.
 * The api-access-control bounded context will consume it during token issuance.
 */
export interface VerificationReceiptStore {
  store(receiptId: string, clientIdentifier: string): Promise<void>;
}
