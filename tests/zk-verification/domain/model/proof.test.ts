// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Proof } from "../../../../src/zk-verification/domain/model/proof.js";
import { GroupElement } from "../../../../src/zk-verification/domain/model/group-element.js";
import { ScalarValue } from "../../../../src/zk-verification/domain/model/scalar-value.js";

function validAnnouncement(): GroupElement {
  return GroupElement.fromBytes(new Uint8Array(32).fill(0x42));
}

function validScalar(fill = 0x01): ScalarValue {
  return ScalarValue.fromBytes(new Uint8Array(32).fill(fill));
}

describe("Proof", () => {
  it("should be created with announcement, and two response scalars", () => {
    const proof = Proof.create(validAnnouncement(), validScalar(0x0a), validScalar(0x0b));

    expect(proof.announcement.toBytes()).toEqual(new Uint8Array(32).fill(0x42));
    expect(proof.responseS.toBytes()).toEqual(new Uint8Array(32).fill(0x0a));
    expect(proof.responseR.toBytes()).toEqual(new Uint8Array(32).fill(0x0b));
  });

  it("should reject a proof with identity element as announcement", () => {
    const identity = GroupElement.fromBytes(new Uint8Array(32).fill(0x00));

    expect(() => Proof.create(identity, validScalar(), validScalar())).toThrow(
      "Announcement must not be the identity element",
    );
  });

  it("should accept a proof with zero response scalar (algebraically valid)", () => {
    const zeroScalar = ScalarValue.fromBytes(new Uint8Array(32).fill(0x00));

    const proof = Proof.create(validAnnouncement(), zeroScalar, validScalar());
    expect(proof.responseS.isZero()).toBe(true);
  });

  it("should accept a proof where both response scalars are zero", () => {
    const zeroScalar = ScalarValue.fromBytes(new Uint8Array(32).fill(0x00));

    const proof = Proof.create(validAnnouncement(), zeroScalar, zeroScalar);
    expect(proof.responseS.isZero()).toBe(true);
    expect(proof.responseR.isZero()).toBe(true);
  });

  it("should serialize to bytes: announcement || z_s || z_r", () => {
    const proof = Proof.create(validAnnouncement(), validScalar(0x0a), validScalar(0x0b));

    const bytes = proof.toBytes();
    expect(bytes.length).toBe(32 + 32 + 32);
    expect(bytes.slice(0, 32)).toEqual(new Uint8Array(32).fill(0x42));
    expect(bytes.slice(32, 64)).toEqual(new Uint8Array(32).fill(0x0a));
    expect(bytes.slice(64, 96)).toEqual(new Uint8Array(32).fill(0x0b));
  });

  it("should reject a proof whose serialized size is not 96 bytes", () => {
    expect(() => Proof.fromBytes(new Uint8Array(95))).toThrow(
      "Proof must be exactly 96 bytes",
    );
    expect(() => Proof.fromBytes(new Uint8Array(97))).toThrow(
      "Proof must be exactly 96 bytes",
    );
  });

  it("should deserialize from 96 bytes and reject identity announcement", () => {
    const bytes = new Uint8Array(96).fill(0x00); // identity announcement
    expect(() => Proof.fromBytes(bytes)).toThrow(
      "Announcement must not be the identity element",
    );
  });

  it("should roundtrip serialize/deserialize", () => {
    const original = Proof.create(validAnnouncement(), validScalar(0x0a), validScalar(0x0b));
    const restored = Proof.fromBytes(original.toBytes());

    expect(restored.announcement.equals(original.announcement)).toBe(true);
    expect(restored.responseS.equals(original.responseS)).toBe(true);
    expect(restored.responseR.equals(original.responseR)).toBe(true);
  });
});
