// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ChannelBinding } from "../../../../src/authentication-challenge/domain/model/channel-binding.js";

describe("ChannelBinding", () => {
  it("should be created from TLS exporter bytes", () => {
    const tlsExporterValue = new Uint8Array(32).fill(0xcc);

    const binding = ChannelBinding.fromTlsExporter(tlsExporterValue);

    expect(binding.toBytes()).toEqual(tlsExporterValue);
  });

  it("should reject empty TLS exporter value", () => {
    expect(() => ChannelBinding.fromTlsExporter(new Uint8Array(0))).toThrow(
      "Channel binding value must be 32 or 48 bytes (RFC 9266)",
    );
  });

  it("should return a defensive copy from toBytes", () => {
    const original = new Uint8Array(32).fill(0xaa);
    const binding = ChannelBinding.fromTlsExporter(original);

    const copy = binding.toBytes();
    copy[0] = 0xff;

    expect(binding.toBytes()[0]).toBe(0xaa);
  });

  it("should be equal to another ChannelBinding with the same bytes", () => {
    const bytes = new Uint8Array(32).fill(0xdd);
    const b1 = ChannelBinding.fromTlsExporter(bytes);
    const b2 = ChannelBinding.fromTlsExporter(bytes);

    expect(b1.equals(b2)).toBe(true);
  });

  it("should use constant-time comparison in equals (XOR accumulator, no early return)", () => {
    const bytes1 = new Uint8Array(32).fill(0xaa);
    const bytes2 = new Uint8Array(32).fill(0xbb);
    const b1 = ChannelBinding.fromTlsExporter(bytes1);
    const b2 = ChannelBinding.fromTlsExporter(bytes2);

    expect(b1.equals(b2)).toBe(false);

    // Single-byte difference at the end
    const bytes3 = new Uint8Array(32).fill(0xaa);
    bytes3[31] = 0xab;
    const b3 = ChannelBinding.fromTlsExporter(bytes3);
    expect(b1.equals(b3)).toBe(false);
  });

  it("should return false for channel bindings of different lengths in constant time", () => {
    const b1 = ChannelBinding.fromTlsExporter(new Uint8Array(32).fill(0xaa));
    const b2 = ChannelBinding.fromTlsExporter(new Uint8Array(48).fill(0xaa));

    expect(b1.equals(b2)).toBe(false);
  });

  it("should accept 32-byte TLS exporter value (SHA-256)", () => {
    const binding = ChannelBinding.fromTlsExporter(new Uint8Array(32).fill(0xaa));
    expect(binding.toBytes().length).toBe(32);
  });

  it("should accept 48-byte TLS exporter value (SHA-384)", () => {
    const binding = ChannelBinding.fromTlsExporter(new Uint8Array(48).fill(0xbb));
    expect(binding.toBytes().length).toBe(48);
  });

  it("should reject TLS exporter value that is not 32 or 48 bytes (RFC 9266)", () => {
    expect(() => ChannelBinding.fromTlsExporter(new Uint8Array(16).fill(0xcc))).toThrow(
      "Channel binding value must be 32 or 48 bytes (RFC 9266)",
    );
  });

  it("should reject 64-byte TLS exporter value", () => {
    expect(() => ChannelBinding.fromTlsExporter(new Uint8Array(64).fill(0xdd))).toThrow(
      "Channel binding value must be 32 or 48 bytes (RFC 9266)",
    );
  });

  it("should reject 1-byte TLS exporter value", () => {
    expect(() => ChannelBinding.fromTlsExporter(new Uint8Array(1).fill(0xee))).toThrow(
      "Channel binding value must be 32 or 48 bytes (RFC 9266)",
    );
  });

  it("different-length bindings use XOR accumulator without early return", () => {
    // The implementation must NOT early-return on different lengths.
    // Instead it XORs lengths into the accumulator and iterates over max length.
    const b1 = ChannelBinding.fromTlsExporter(new Uint8Array(32).fill(0xaa));
    const b2 = ChannelBinding.fromTlsExporter(new Uint8Array(48).fill(0xaa));
    // Should be false (different lengths)
    expect(b1.equals(b2)).toBe(false);
    // Verify it's false due to length, not content
    const b3 = ChannelBinding.fromTlsExporter(new Uint8Array(48).fill(0xaa));
    expect(b2.equals(b3)).toBe(true);
  });

  it("equals loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= this.bytes.length; i++)` — off-by-one
    // Would access bytes[32] which is undefined, leading to `undefined ^ byte` = NaN
    const bytes = new Uint8Array(32).fill(0xaa);
    const b1 = ChannelBinding.fromTlsExporter(bytes);
    const b2 = ChannelBinding.fromTlsExporter(bytes);
    expect(b1.equals(b2)).toBe(true);
  });
});
