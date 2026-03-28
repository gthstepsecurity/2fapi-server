// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenId } from "./token-id.js";
import type { Audience } from "./audience.js";
import type { AuthenticationLevel } from "./authentication-level.js";

export interface TokenClaimsInput {
  readonly iss: string;
  readonly sub: string;
  readonly aud: Audience;
  readonly exp: number;
  readonly iat: number;
  readonly jti: TokenId;
  readonly cnf: string;
  readonly level: AuthenticationLevel;
}

export class TokenClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: Audience;
  readonly exp: number;
  readonly iat: number;
  readonly jti: TokenId;
  readonly cnf: string;
  readonly level: AuthenticationLevel;

  private constructor(input: TokenClaimsInput) {
    this.iss = input.iss;
    this.sub = input.sub;
    this.aud = input.aud;
    this.exp = input.exp;
    this.iat = input.iat;
    this.jti = input.jti;
    this.cnf = input.cnf;
    this.level = input.level;
  }

  static create(input: TokenClaimsInput): TokenClaims {
    if (input.iss.length === 0) {
      throw new Error("Issuer must not be empty");
    }
    if (input.sub.length === 0) {
      throw new Error("Subject must not be empty");
    }
    if (input.exp <= input.iat) {
      throw new Error("Expiration must be after issuedAt");
    }
    if (input.cnf.length === 0) {
      throw new Error("Channel binding hash must not be empty");
    }
    return new TokenClaims(input);
  }

  isExpiredAt(nowMs: number): boolean {
    return nowMs >= this.exp;
  }

  hasAudience(expected: Audience): boolean {
    return this.aud.equals(expected);
  }

  /**
   * Constant-time comparison using XOR accumulator pattern.
   * Prevents timing side-channel attacks on channel binding verification.
   * Length mismatch is folded into the accumulator to avoid early return.
   */
  hasChannelBinding(expectedHash: string): boolean {
    const a = this.cnf;
    const b = expectedHash;
    const maxLen = Math.max(a.length, b.length);
    let acc = a.length ^ b.length; // non-zero if lengths differ
    for (let i = 0; i < maxLen; i++) {
      const ca = i < a.length ? a.charCodeAt(i) : 0;
      const cb = i < b.length ? b.charCodeAt(i) : 0;
      acc |= ca ^ cb;
    }
    return acc === 0;
  }

  /**
   * Produces canonical JSON for signing.
   * Keys are sorted alphabetically for deterministic output.
   */
  serialize(): string {
    const obj: Record<string, unknown> = {
      aud: this.aud.value,
      cnf: this.cnf,
      exp: this.exp,
      iat: this.iat,
      iss: this.iss,
      jti: this.jti.toString(),
      level: this.level,
      sub: this.sub,
    };
    return JSON.stringify(obj);
  }
}
