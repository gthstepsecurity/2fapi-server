// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { defineConfig } from "vitest/config";

/**
 * Vitest configuration for integration tests.
 *
 * These tests run against REAL infrastructure (PostgreSQL, Redis, napi-rs)
 * and are NOT included in the default `vitest run` command.
 *
 * Usage:
 *   npx vitest run --config tests/integration/vitest.integration.config.ts
 *
 * Prerequisites:
 *   docker compose up -d
 *   cd crypto-core/napi && cargo build --release && cd ../..
 */
export default defineConfig({
  test: {
    include: ["tests/integration/**/*.integration.test.ts"],
    globals: true,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
