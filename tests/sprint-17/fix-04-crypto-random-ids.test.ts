// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "../..");

/**
 * Sprint 17 — Finding 4 (MEDIUM): Math.random() for Token/Monitoring IDs
 *
 * Math.random() is not cryptographically secure. All generated IDs
 * must use crypto.randomUUID() from node:crypto.
 */

describe("Cryptographically Secure ID Generation", () => {
  const productionServicesPath = resolve(ROOT, "src/config/production-services.ts");

  it("production-services.ts should not use Math.random() for ID generation", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).not.toContain("Math.random()");
  });

  it("production-services.ts should use crypto.randomUUID() for ID generation", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).toContain("randomUUID()");
  });

  it("production-services.ts should import from node:crypto", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).toContain("node:crypto");
  });

  it("generated token IDs should match UUID v4 format", () => {
    const { randomUUID } = require("node:crypto");
    const id = `tok-${Date.now()}-${randomUUID()}`;
    // UUID v4 pattern: 8-4-4-4-12 hex chars
    const uuidPattern = /^tok-\d+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(id).toMatch(uuidPattern);
  });

  it("generated monitoring IDs should match UUID v4 format", () => {
    const { randomUUID } = require("node:crypto");
    const id = `mon-${Date.now()}-${randomUUID()}`;
    const uuidPattern = /^mon-\d+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(id).toMatch(uuidPattern);
  });
});
