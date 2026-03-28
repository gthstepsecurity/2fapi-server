// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export const AuthenticationLevel = {
  STANDARD: "standard",
  ELEVATED: "elevated",
} as const;

export type AuthenticationLevel =
  (typeof AuthenticationLevel)[keyof typeof AuthenticationLevel];

export const STANDARD_TTL_MS = 15 * 60 * 1000;
export const ELEVATED_TTL_MS = 5 * 60 * 1000;

export function ttlForLevel(level: AuthenticationLevel): number {
  switch (level) {
    case AuthenticationLevel.STANDARD:
      return STANDARD_TTL_MS;
    case AuthenticationLevel.ELEVATED:
      return ELEVATED_TTL_MS;
  }
}
