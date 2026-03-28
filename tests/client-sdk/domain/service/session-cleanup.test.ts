// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { SessionCleanup } from "../../../../packages/client-sdk/src/domain/service/session-cleanup.js";

describe("SessionCleanup", () => {
  const zeroize = (buf: Uint8Array) => buf.fill(0);
  const cleanup = new SessionCleanup(zeroize);

  it("zeroizes all WASM buffers", () => {
    const buf1 = new Uint8Array(32).fill(0xFF);
    const buf2 = new Uint8Array(16).fill(0xAA);

    cleanup.execute({
      wasmBuffers: [buf1, buf2],
      jsReferences: [],
      sessionStorageKeys: [],
    });

    expect(buf1.every(b => b === 0)).toBe(true);
    expect(buf2.every(b => b === 0)).toBe(true);
  });

  it("nullifies JS references", () => {
    const ref1 = { value: "secret" as unknown };
    const ref2 = { value: new Uint8Array(32) as unknown };

    cleanup.execute({
      wasmBuffers: [],
      jsReferences: [ref1, ref2],
      sessionStorageKeys: [],
    });

    expect(ref1.value).toBeNull();
    expect(ref2.value).toBeNull();
  });

  it("clears session storage keys", () => {
    const store = new Map<string, string>();
    store.set("2fapi-session", "jwt-token");
    store.set("2fapi-email", "alice@acme.com");
    store.set("unrelated", "keep");

    const mockStorage = {
      removeItem: (key: string) => store.delete(key),
    } as Storage;

    cleanup.execute({
      wasmBuffers: [],
      jsReferences: [],
      sessionStorage: mockStorage,
      sessionStorageKeys: ["2fapi-session", "2fapi-email"],
    });

    expect(store.has("2fapi-session")).toBe(false);
    expect(store.has("2fapi-email")).toBe(false);
    expect(store.has("unrelated")).toBe(true);
  });

  it("expires session cookie", () => {
    let cookieExpired = false;

    cleanup.execute({
      wasmBuffers: [],
      jsReferences: [],
      sessionStorageKeys: [],
      expireCookie: () => { cookieExpired = true; },
    });

    expect(cookieExpired).toBe(true);
  });

  it("reports success when all steps complete", () => {
    const result = cleanup.execute({
      wasmBuffers: [new Uint8Array(32).fill(0xFF)],
      jsReferences: [{ value: "x" }],
      sessionStorageKeys: [],
    });
    expect(result.success).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("continues on error and reports failures", () => {
    const throwingCleanup = new SessionCleanup(() => { throw new Error("wasm gone"); });

    const result = throwingCleanup.execute({
      wasmBuffers: [new Uint8Array(32)],
      jsReferences: [],
      sessionStorageKeys: [],
    });

    expect(result.success).toBe(false);
    expect(result.errors).toContain("wasm_zeroize_failed");
  });
});
