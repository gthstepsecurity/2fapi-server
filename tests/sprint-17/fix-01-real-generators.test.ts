// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "../..");

/**
 * Sprint 17 — Finding 1 (CRITICAL): Real Ristretto255 Generators G/H
 *
 * Verifies that:
 * - production-services.ts no longer uses placeholder bytes (fill(0x01)/fill(0x02))
 * - production-services.ts loads generators from the NAPI module
 * - NAPI Rust lib.rs exports getGeneratorG() and getGeneratorH()
 * - TypeScript declarations include getGeneratorG() and getGeneratorH()
 */

describe("Real Ristretto255 Generators", () => {
  const productionServicesPath = resolve(ROOT, "src/config/production-services.ts");
  const napiLibPath = resolve(ROOT, "crypto-core/napi/src/lib.rs");
  const napiDtsPath = resolve(ROOT, "crypto-core/napi/index.d.ts");

  it("production-services.ts should not contain fill(0x01) placeholder generator", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).not.toContain("fill(0x01)");
  });

  it("production-services.ts should not contain fill(0x02) placeholder generator", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).not.toContain("fill(0x02)");
  });

  it("production-services.ts should load generatorG from the native crypto module", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).toContain("getGeneratorG");
  });

  it("production-services.ts should load generatorH from the native crypto module", () => {
    const source = readFileSync(productionServicesPath, "utf-8");
    expect(source).toContain("getGeneratorH");
  });

  it("NAPI Rust lib.rs should export get_generator_g function", () => {
    const source = readFileSync(napiLibPath, "utf-8");
    expect(source).toContain("pub fn get_generator_g");
    expect(source).toContain("#[napi]");
  });

  it("NAPI Rust lib.rs should export get_generator_h function", () => {
    const source = readFileSync(napiLibPath, "utf-8");
    expect(source).toContain("pub fn get_generator_h");
  });

  it("NAPI Rust generators should use crypto generators module", () => {
    const source = readFileSync(napiLibPath, "utf-8");
    expect(source).toContain("crypto::generators::generator_g()");
    expect(source).toContain("crypto::generators::generator_h()");
  });

  it("TypeScript declarations should include getGeneratorG", () => {
    const source = readFileSync(napiDtsPath, "utf-8");
    expect(source).toContain("getGeneratorG");
  });

  it("TypeScript declarations should include getGeneratorH", () => {
    const source = readFileSync(napiDtsPath, "utf-8");
    expect(source).toContain("getGeneratorH");
  });

  it("TypeScript ambient module should include getGeneratorG and getGeneratorH", () => {
    const ambientPath = resolve(ROOT, "src/types/crypto-native.d.ts");
    const source = readFileSync(ambientPath, "utf-8");
    expect(source).toContain("getGeneratorG");
    expect(source).toContain("getGeneratorH");
  });
});
