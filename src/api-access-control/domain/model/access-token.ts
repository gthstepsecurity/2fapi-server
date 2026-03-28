// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TokenClaims } from "./token-claims.js";

export class AccessToken {
  private readonly _signedBytes: Uint8Array;

  private constructor(
    readonly claims: TokenClaims,
    signedBytes: Uint8Array,
  ) {
    this._signedBytes = new Uint8Array(signedBytes);
  }

  static issue(claims: TokenClaims, signedBytes: Uint8Array): AccessToken {
    return new AccessToken(claims, signedBytes);
  }

  get signedBytes(): Uint8Array {
    return new Uint8Array(this._signedBytes);
  }

  /**
   * Returns the bearer token string (base64url-encoded signed bytes).
   * Suitable for use in HTTP Authorization headers.
   */
  toBearer(): string {
    return base64UrlEncode(this._signedBytes);
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
