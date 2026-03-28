// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export const FirstFactorType = {
  ZKP: "zkp",
  LEGACY_API_KEY: "legacy-api-key",
} as const;

export type FirstFactorType = (typeof FirstFactorType)[keyof typeof FirstFactorType];
