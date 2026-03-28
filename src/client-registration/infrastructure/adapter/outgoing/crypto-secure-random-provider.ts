// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomInt } from "node:crypto";
import type { SecureRandomProvider } from "../../../domain/port/outgoing/secure-random-provider.js";

/**
 * Cryptographically secure random provider using Node.js crypto.randomInt.
 * Produces uniform random integers in [0, max) without modulo bias.
 */
export class CryptoSecureRandomProvider implements SecureRandomProvider {
  randomIndex(max: number): number {
    return randomInt(max);
  }
}
