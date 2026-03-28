// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VaultAttemptCounter } from "../../../../packages/client-sdk/src/domain/model/vault-attempt-counter.js";

describe("VaultAttemptCounter", () => {
  it("creates with zero failures", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    expect(counter.consecutiveFailures).toBe(0);
    expect(counter.isWiped).toBe(false);
  });

  it("increments on failure", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    const incremented = counter.recordFailure();
    expect(incremented.consecutiveFailures).toBe(1);
  });

  it("is immutable — returns new instance on failure", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    const incremented = counter.recordFailure();
    expect(counter.consecutiveFailures).toBe(0);
    expect(incremented.consecutiveFailures).toBe(1);
  });

  it("triggers wipe at default threshold (3)", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure(); // 1
    counter = counter.recordFailure(); // 2
    counter = counter.recordFailure(); // 3
    expect(counter.isWiped).toBe(true);
  });

  it("triggers wipe at custom threshold", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123", 5);
    counter = counter.recordFailure().recordFailure().recordFailure().recordFailure();
    expect(counter.isWiped).toBe(false);
    counter = counter.recordFailure(); // 5
    expect(counter.isWiped).toBe(true);
  });

  it("resets on successful auth", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure(); // 2 failures
    counter = counter.recordSuccess();
    expect(counter.consecutiveFailures).toBe(0);
    expect(counter.isWiped).toBe(false);
  });

  it("cannot un-wipe via success", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure(); // wiped
    counter = counter.recordSuccess();
    expect(counter.isWiped).toBe(true); // still wiped
  });

  it("reports attempts remaining correctly", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    expect(counter.attemptsRemaining).toBe(3);
    counter = counter.recordFailure();
    expect(counter.attemptsRemaining).toBe(2);
    counter = counter.recordFailure();
    expect(counter.attemptsRemaining).toBe(1);
    counter = counter.recordFailure();
    expect(counter.attemptsRemaining).toBe(0);
  });

  it("restores from persisted state", () => {
    const counter = VaultAttemptCounter.restore("client-1", "dev-abc123", 2, false, 3);
    expect(counter.consecutiveFailures).toBe(2);
    expect(counter.attemptsRemaining).toBe(1);
    expect(counter.isWiped).toBe(false);
  });

  it("restores wiped state", () => {
    const counter = VaultAttemptCounter.restore("client-1", "dev-abc123", 3, true, 3);
    expect(counter.isWiped).toBe(true);
    expect(counter.attemptsRemaining).toBe(0);
  });

  it("preserves clientId and deviceId", () => {
    const counter = VaultAttemptCounter.create("client-alice", "dev-laptop");
    expect(counter.clientId).toBe("client-alice");
    expect(counter.deviceId).toBe("dev-laptop");
  });

  it("threshold of 0 means disabled (no wipe ever)", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123", 0);
    for (let i = 0; i < 100; i++) {
      counter = counter.recordFailure();
    }
    expect(counter.isWiped).toBe(false);
  });

  it("minimum threshold is 3 when non-zero", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123", 1);
    expect(counter.threshold).toBe(3);
  });

  it("threshold of 2 is clamped to 3", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123", 2);
    expect(counter.threshold).toBe(3);
  });

  it("threshold of 3 is kept as-is", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123", 3);
    expect(counter.threshold).toBe(3);
  });

  it("recordFailure on wiped counter is a no-op", () => {
    let counter = VaultAttemptCounter.create("client-1", "dev-abc123");
    counter = counter.recordFailure().recordFailure().recordFailure(); // wiped
    const afterFailure = counter.recordFailure();
    expect(afterFailure.consecutiveFailures).toBe(counter.consecutiveFailures);
    expect(afterFailure.isWiped).toBe(true);
  });

  it("attemptsRemaining is 0 when threshold is 0 (disabled)", () => {
    const counter = VaultAttemptCounter.create("client-1", "dev-abc123", 0);
    expect(counter.attemptsRemaining).toBe(0);
  });
});
