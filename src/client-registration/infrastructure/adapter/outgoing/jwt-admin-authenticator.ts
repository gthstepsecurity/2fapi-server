// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { createHmac, timingSafeEqual } from "node:crypto";
import type { AdminAuthenticator } from "../../../domain/port/outgoing/admin-authenticator.js";

/**
 * HMAC-based implementation of AdminAuthenticator.
 *
 * Verifies admin identity by checking that the provided identity string
 * matches an HMAC-SHA256 signature computed with the admin secret.
 *
 * The admin identity can be either:
 * 1. A raw secret that is compared against the configured admin secret
 * 2. An HMAC-signed token in the format "timestamp:hmac" that is verified
 *    against the admin secret
 *
 * For simplicity, this implementation uses direct secret comparison
 * with constant-time equality. The secret is loaded from the ADMIN_SECRET
 * environment variable.
 *
 * Security properties:
 * - Constant-time comparison prevents timing attacks
 * - Secret is stored in memory only (loaded from environment)
 * - Minimum secret length enforced (32 characters)
 */
export class JwtAdminAuthenticator implements AdminAuthenticator {
  private readonly secretBuffer: Buffer;

  constructor(adminSecret: string) {
    if (adminSecret.length < 32) {
      throw new Error(
        "Admin secret must be at least 32 characters long for security",
      );
    }
    this.secretBuffer = Buffer.from(adminSecret, "utf-8");
  }

  /**
   * Creates an authenticator from the ADMIN_SECRET environment variable.
   * @throws if ADMIN_SECRET is not set or too short
   */
  static fromEnvironment(): JwtAdminAuthenticator {
    const secret = process.env["ADMIN_SECRET"];
    if (secret === undefined || secret === "") {
      throw new Error(
        "ADMIN_SECRET environment variable is required for admin authentication",
      );
    }
    return new JwtAdminAuthenticator(secret);
  }

  async isValidAdmin(adminIdentity: string): Promise<boolean> {
    if (adminIdentity.length === 0) {
      return false;
    }

    // Check if the identity contains a timestamp-based HMAC token
    const separatorIndex = adminIdentity.indexOf(":");
    if (separatorIndex > 0) {
      return this.verifyHmacToken(adminIdentity, separatorIndex);
    }

    // Direct secret comparison (for simple API key auth)
    return this.constantTimeCompare(adminIdentity);
  }

  /**
   * Verifies an HMAC-based admin token in the format "timestamp:hmac".
   * The HMAC is computed as HMAC-SHA256(secret, timestamp).
   */
  private verifyHmacToken(token: string, separatorIndex: number): boolean {
    const timestamp = token.substring(0, separatorIndex);
    const providedHmac = token.substring(separatorIndex + 1);

    // Verify the HMAC
    const expectedHmac = createHmac("sha256", this.secretBuffer)
      .update(timestamp)
      .digest("hex");

    // Constant-time comparison of HMAC values
    try {
      const providedBuffer = Buffer.from(providedHmac, "hex");
      const expectedBuffer = Buffer.from(expectedHmac, "hex");

      if (providedBuffer.length !== expectedBuffer.length) {
        return false;
      }

      return timingSafeEqual(providedBuffer, expectedBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Compares the provided identity directly against the admin secret
   * using constant-time comparison.
   */
  private constantTimeCompare(identity: string): boolean {
    const identityBuffer = Buffer.from(identity, "utf-8");

    if (identityBuffer.length !== this.secretBuffer.length) {
      // Still do a comparison to maintain constant time behavior
      // against a dummy buffer to prevent length-based timing leaks
      const dummy = Buffer.alloc(identityBuffer.length);
      timingSafeEqual(identityBuffer, dummy);
      return false;
    }

    return timingSafeEqual(identityBuffer, this.secretBuffer);
  }
}
