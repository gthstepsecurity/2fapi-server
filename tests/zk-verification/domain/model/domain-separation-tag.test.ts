// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DomainSeparationTag } from "../../../../src/zk-verification/domain/model/domain-separation-tag.js";

describe("DomainSeparationTag", () => {
  it("should be created with the protocol tag", () => {
    const tag = DomainSeparationTag.protocol();
    expect(tag.value).toBe("2FApi-v1.0-Sigma");
  });

  it("should be created from a custom string", () => {
    const tag = DomainSeparationTag.fromString("Custom-v2.0");
    expect(tag.value).toBe("Custom-v2.0");
  });

  it("should reject an empty tag", () => {
    expect(() => DomainSeparationTag.fromString("")).toThrow(
      "Domain separation tag must not be empty",
    );
  });

  it("should serialize to UTF-8 bytes", () => {
    const tag = DomainSeparationTag.protocol();
    const bytes = tag.toBytes();
    const decoded = new TextDecoder().decode(bytes);
    expect(decoded).toBe("2FApi-v1.0-Sigma");
  });

  it("should be equal to another tag with the same value", () => {
    const a = DomainSeparationTag.protocol();
    const b = DomainSeparationTag.protocol();
    expect(a.equals(b)).toBe(true);
  });

  it("should not be equal to a tag with a different value", () => {
    const a = DomainSeparationTag.protocol();
    const b = DomainSeparationTag.fromString("OtherProtocol-v1.0");
    expect(a.equals(b)).toBe(false);
  });

  describe("distinct tags for enrollment, auth, and rotation", () => {
    it("enrollment tag exists and is distinct from protocol tag", () => {
      const enrollment = DomainSeparationTag.enrollment();
      const protocol = DomainSeparationTag.protocol();
      expect(enrollment.equals(protocol)).toBe(false);
    });

    it("rotation tag exists and is distinct from protocol tag", () => {
      const rotation = DomainSeparationTag.rotation();
      const protocol = DomainSeparationTag.protocol();
      expect(rotation.equals(protocol)).toBe(false);
    });

    it("enrollment tag is distinct from rotation tag", () => {
      const enrollment = DomainSeparationTag.enrollment();
      const rotation = DomainSeparationTag.rotation();
      expect(enrollment.equals(rotation)).toBe(false);
    });

    it("all three tags are pairwise distinct", () => {
      const tags = [
        DomainSeparationTag.protocol(),
        DomainSeparationTag.enrollment(),
        DomainSeparationTag.rotation(),
      ];

      for (let i = 0; i < tags.length; i++) {
        for (let j = i + 1; j < tags.length; j++) {
          expect(tags[i]!.equals(tags[j]!)).toBe(false);
        }
      }
    });

    it("enrollment tag has the expected value", () => {
      const tag = DomainSeparationTag.enrollment();
      expect(tag.value).toBe("2FApi-v1.0-Enrollment");
    });

    it("rotation tag has the expected value", () => {
      const tag = DomainSeparationTag.rotation();
      expect(tag.value).toBe("2FApi-v1.0-Rotation");
    });
  });
});
