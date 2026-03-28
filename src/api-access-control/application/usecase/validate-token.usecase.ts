// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  ValidateToken,
  ValidateTokenRequest,
  ValidateTokenResponse,
} from "../../domain/port/incoming/validate-token.js";
import type { TokenVerifier } from "../../domain/port/outgoing/token-verifier.js";
import type { ClientStatusChecker } from "../../domain/port/outgoing/client-status-checker.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import { TokenValidationChain } from "../../domain/service/token-validation-chain.js";
import { Audience } from "../../domain/model/audience.js";
import type { AuthenticationLevel } from "../../domain/model/authentication-level.js";

const MAX_TOKEN_BYTES = 4096;

interface ParsedClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly exp: number;
  readonly iat: number;
  readonly jti: string;
  readonly cnf: string;
  readonly level: AuthenticationLevel;
}

export class ValidateTokenUseCase implements ValidateToken {
  constructor(
    private readonly tokenVerifier: TokenVerifier,
    private readonly clientStatusChecker: ClientStatusChecker,
    private readonly auditLogger: AuditLogger,
    private readonly clock: Clock,
    private readonly validationChain: TokenValidationChain,
  ) {}

  async execute(request: ValidateTokenRequest): Promise<ValidateTokenResponse> {
    // Format check: empty or oversized
    if (request.bearerToken.length === 0 || request.bearerToken.length > MAX_TOKEN_BYTES) {
      await this.auditDenied("unknown", "invalid_format");
      return { success: false, error: "access_denied" };
    }

    // Decode base64url to bytes
    let tokenBytes: Uint8Array;
    try {
      tokenBytes = base64UrlDecode(request.bearerToken);
    } catch {
      await this.auditDenied("unknown", "malformed_token");
      return { success: false, error: "access_denied" };
    }

    // Verify signature and extract payload
    const payload = await this.tokenVerifier.verify(tokenBytes);

    // Parse claims from payload (always attempt, even on null for timing safety)
    let parsedClaims: ParsedClaims | null = null;
    if (payload !== null) {
      try {
        const json = new TextDecoder().decode(payload);
        const obj = JSON.parse(json) as Record<string, unknown>;
        parsedClaims = {
          iss: obj.iss as string,
          sub: obj.sub as string,
          aud: obj.aud as string,
          exp: obj.exp as number,
          iat: obj.iat as number,
          jti: obj.jti as string,
          cnf: obj.cnf as string,
          level: obj.level as AuthenticationLevel,
        };
      } catch {
        // Parsing failure — treated as signature invalid path
        parsedClaims = null;
      }
    }

    // Build validation input
    const signatureValid = payload !== null && parsedClaims !== null;
    const clientIdentifier = parsedClaims?.sub ?? "unknown";

    // Client status check (ALWAYS executed for timing safety)
    const clientActive = signatureValid
      ? await this.clientStatusChecker.isActive(clientIdentifier)
      : await this.dummyClientStatusCheck();

    // Expected audience
    let expectedAudience: Audience;
    try {
      expectedAudience = Audience.fromString(request.expectedAudience);
    } catch {
      await this.auditDenied(clientIdentifier, "invalid_audience");
      return { success: false, error: "access_denied" };
    }

    // Build dummy claims for timing-safe path when parsing failed
    const effectiveClaims = parsedClaims ?? {
      iss: "",
      sub: "",
      aud: "",
      exp: 0,
      iat: 0,
      jti: "",
      cnf: "",
      level: "standard" as AuthenticationLevel,
    };

    // Create TokenClaims-like object for validation chain
    // We use the raw parsed claims to avoid constructor validation throwing
    const nowMs = this.clock.nowMs();

    let tokenAudience: Audience;
    try {
      tokenAudience = Audience.fromString(
        effectiveClaims.aud.length > 0 ? effectiveClaims.aud : "dummy",
      );
    } catch {
      tokenAudience = Audience.fromString("dummy");
    }

    const validationError = this.validationChain.validate({
      claims: {
        isExpiredAt: (ms: number) => ms >= effectiveClaims.exp,
        hasAudience: (aud: Audience) => tokenAudience.equals(aud),
        hasChannelBinding: (hash: string) => {
          // Constant-time comparison — no early return on length mismatch
          const a = effectiveClaims.cnf;
          const b = hash;
          const maxLen = Math.max(a.length, b.length);
          let acc = a.length ^ b.length;
          for (let i = 0; i < maxLen; i++) {
            const ca = i < a.length ? a.charCodeAt(i) : 0;
            const cb = i < b.length ? b.charCodeAt(i) : 0;
            acc |= ca ^ cb;
          }
          return acc === 0;
        },
      } as import("../../domain/model/token-claims.js").TokenClaims,
      signatureValid,
      nowMs,
      expectedAudience,
      expectedChannelBindingHash: request.channelBindingHash,
      clientActive,
    });

    if (validationError !== null) {
      await this.auditDenied(clientIdentifier, validationError.code);
      return { success: false, error: "access_denied" };
    }

    // Success
    await this.auditLogger.log({
      action: "access_granted",
      clientIdentifier,
      timestamp: new Date(),
      details: {
        audience: effectiveClaims.aud,
        level: effectiveClaims.level,
        tokenId: effectiveClaims.jti,
      },
    });

    return {
      success: true,
      clientIdentifier,
      audience: effectiveClaims.aud,
      level: effectiveClaims.level,
    };
  }

  private async auditDenied(clientIdentifier: string, reason: string): Promise<void> {
    await this.auditLogger.log({
      action: "access_denied",
      clientIdentifier,
      timestamp: new Date(),
      details: { reason },
    });
  }

  /**
   * Dummy client status check executed on the failure path
   * to maintain constant-time behavior.
   */
  private async dummyClientStatusCheck(): Promise<boolean> {
    await this.clientStatusChecker.isActive("__dummy__");
    return false;
  }
}

function base64UrlDecode(input: string): Uint8Array {
  // Restore standard base64
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
