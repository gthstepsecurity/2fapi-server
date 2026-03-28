// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * FIX L-01: unit tests for isValidDomainSeparationTag.
 *
 * Verifies charset restriction (ASCII [a-zA-Z0-9._-] only)
 * and length bounds (1-64 chars).
 */
import { describe, it, expect } from "vitest";
import { isValidDomainSeparationTag } from "../../src/api-gateway/validation.js";

describe("isValidDomainSeparationTag (FIX L-01)", () => {
  // --- Valid tags ---

  it("accepts standard protocol tag", () => {
    expect(isValidDomainSeparationTag("2FApi-v1.0-Sigma")).toBe(true);
  });

  it("accepts tag with all allowed character classes", () => {
    expect(isValidDomainSeparationTag("Ghost-Protocol_v2.1-test")).toBe(true);
  });

  it("accepts single character tag", () => {
    expect(isValidDomainSeparationTag("x")).toBe(true);
  });

  it("accepts tag of exactly 64 characters", () => {
    expect(isValidDomainSeparationTag("a".repeat(64))).toBe(true);
  });

  // --- Length violations ---

  it("rejects empty string", () => {
    expect(isValidDomainSeparationTag("")).toBe(false);
  });

  it("rejects tag exceeding 64 characters", () => {
    expect(isValidDomainSeparationTag("a".repeat(65))).toBe(false);
  });

  it("rejects 10000 character tag", () => {
    expect(isValidDomainSeparationTag("a".repeat(10000))).toBe(false);
  });

  // --- Charset violations: Unicode attacks ---

  it("rejects Cyrillic homoglyph (а U+0430 vs a U+0061)", () => {
    expect(isValidDomainSeparationTag("2F\u0430pi")).toBe(false);
  });

  it("rejects Cyrillic А (U+0410) that looks like Latin A", () => {
    expect(isValidDomainSeparationTag("2F\u0410pi")).toBe(false);
  });

  it("rejects Greek Sigma (Σ U+03A3)", () => {
    expect(isValidDomainSeparationTag("2FApi-\u03A3igma")).toBe(false);
  });

  it("rejects right-to-left mark (U+200F)", () => {
    expect(isValidDomainSeparationTag("2FApi\u200Fv1")).toBe(false);
  });

  it("rejects zero-width joiner (U+200D)", () => {
    expect(isValidDomainSeparationTag("2F\u200DApi")).toBe(false);
  });

  it("rejects zero-width space (U+200B)", () => {
    expect(isValidDomainSeparationTag("2F\u200BApi")).toBe(false);
  });

  // --- Charset violations: ASCII specials ---

  it("rejects spaces", () => {
    expect(isValidDomainSeparationTag("2FApi v1")).toBe(false);
  });

  it("rejects forward slash", () => {
    expect(isValidDomainSeparationTag("2FApi/v1")).toBe(false);
  });

  it("rejects colon", () => {
    expect(isValidDomainSeparationTag("urn:2fapi:sigma")).toBe(false);
  });

  it("rejects at sign", () => {
    expect(isValidDomainSeparationTag("user@domain")).toBe(false);
  });

  it("rejects newline", () => {
    expect(isValidDomainSeparationTag("2FApi\nv1")).toBe(false);
  });

  it("rejects null byte", () => {
    expect(isValidDomainSeparationTag("2FApi\0v1")).toBe(false);
  });

  it("rejects tab", () => {
    expect(isValidDomainSeparationTag("2FApi\tv1")).toBe(false);
  });

  // --- Allowed characters confirmed ---

  it("accepts lowercase letters", () => {
    expect(isValidDomainSeparationTag("abcdefghijklmnopqrstuvwxyz")).toBe(true);
  });

  it("accepts uppercase letters", () => {
    expect(isValidDomainSeparationTag("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
  });

  it("accepts digits", () => {
    expect(isValidDomainSeparationTag("0123456789")).toBe(true);
  });

  it("accepts dots", () => {
    expect(isValidDomainSeparationTag("v1.0.0")).toBe(true);
  });

  it("accepts underscores", () => {
    expect(isValidDomainSeparationTag("domain_sep_tag")).toBe(true);
  });

  it("accepts hyphens", () => {
    expect(isValidDomainSeparationTag("domain-sep-tag")).toBe(true);
  });
});
