// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";
import type { IdGenerator } from "../../../domain/port/outgoing/id-generator.js";
import { ClientId } from "../../../domain/model/client-id.js";

export class CryptoRandomIdGenerator implements IdGenerator {
  generate(): ClientId {
    // Note: the intermediate Buffer from randomBytes is not zeroed after copy.
    // This is acceptable for opaque identifiers (not secrets).
    // For secret material, use buf.fill(0) after copying to Uint8Array.
    const bytes = randomBytes(16);
    return ClientId.fromBytes(new Uint8Array(bytes));
  }
}
