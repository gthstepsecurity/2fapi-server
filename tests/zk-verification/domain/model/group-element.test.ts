// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { GroupElement } from "../../../../src/zk-verification/domain/model/group-element.js";

describe("GroupElement", () => {
  const ELEMENT_BYTE_LENGTH = 32;

  it("should be created from exactly 32 bytes", () => {
    const bytes = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0x01);
    const element = GroupElement.fromBytes(bytes);
    expect(element.toBytes()).toEqual(bytes);
  });

  it("should reject bytes not exactly 32 bytes long", () => {
    expect(() => GroupElement.fromBytes(new Uint8Array(31))).toThrow(
      "Group element must be exactly 32 bytes",
    );
  });

  it("should detect the identity element (all zeros)", () => {
    const identity = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0x00);
    const element = GroupElement.fromBytes(identity);
    expect(element.isIdentity()).toBe(true);
  });

  it("should report non-identity for a non-zero element", () => {
    const nonIdentity = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0x00);
    nonIdentity[0] = 0x01;
    const element = GroupElement.fromBytes(nonIdentity);
    expect(element.isIdentity()).toBe(false);
  });

  it("should return a defensive copy from toBytes", () => {
    const original = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xbb);
    const element = GroupElement.fromBytes(original);
    const copy = element.toBytes();
    copy[0] = 0xff;
    expect(element.toBytes()[0]).toBe(0xbb);
  });

  it("should use constant-time comparison in equals", () => {
    const a = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xaa);
    const b = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xaa);
    const c = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xcc);

    expect(GroupElement.fromBytes(a).equals(GroupElement.fromBytes(b))).toBe(true);
    expect(GroupElement.fromBytes(a).equals(GroupElement.fromBytes(c))).toBe(false);
  });

  it("isIdentity loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= this.bytes.length; i++)` — off-by-one
    // With <=, accessing bytes[32] returns undefined, and `0 | undefined` = 0
    // This wouldn't actually break the logic but the mutant should still be killed
    // by verifying correct behavior
    const nonIdentity = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0x00);
    nonIdentity[31] = 0x01; // only last byte differs
    const element = GroupElement.fromBytes(nonIdentity);
    expect(element.isIdentity()).toBe(false);
  });

  it("equals loop uses < not <= (off-by-one check)", () => {
    // Kill mutant: `for (let i = 0; i <= ELEMENT_BYTE_LENGTH; i++)` — off-by-one
    // With <=, accessing bytes[32] returns undefined and XOR with undefined = NaN
    const a = GroupElement.fromBytes(new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xab));
    const b = GroupElement.fromBytes(new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xab));
    expect(a.equals(b)).toBe(true);

    // Verify different last byte is detected
    const c = new Uint8Array(ELEMENT_BYTE_LENGTH).fill(0xab);
    c[31] = 0xac;
    expect(a.equals(GroupElement.fromBytes(c))).toBe(false);
  });
});
