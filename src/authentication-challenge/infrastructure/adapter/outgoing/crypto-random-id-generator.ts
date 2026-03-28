// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";
import type { IdGenerator } from "../../../domain/port/outgoing/id-generator.js";

export class CryptoRandomIdGenerator implements IdGenerator {
  generate(): string {
    return randomBytes(16).toString("hex");
  }
}
