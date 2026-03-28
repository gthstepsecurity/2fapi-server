// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { ChallengeId } from "../../../../src/authentication-challenge/domain/model/challenge-id.js";

describe("ChallengeId", () => {
  it("should be created from a non-empty string", () => {
    const id = ChallengeId.fromString("challenge-abc-123");

    expect(id.value).toBe("challenge-abc-123");
  });

  it("should reject an empty string", () => {
    expect(() => ChallengeId.fromString("")).toThrow("Challenge ID must not be empty");
  });

  it("should be equal to another ChallengeId with the same value", () => {
    const id1 = ChallengeId.fromString("abc");
    const id2 = ChallengeId.fromString("abc");

    expect(id1.equals(id2)).toBe(true);
  });

  it("should not be equal to a ChallengeId with a different value", () => {
    const id1 = ChallengeId.fromString("abc");
    const id2 = ChallengeId.fromString("def");

    expect(id1.equals(id2)).toBe(false);
  });
});
