// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { AnomalyAlert } from "../../../../src/security-monitoring/domain/model/anomaly-alert.js";

describe("AnomalyAlert", () => {
  it("creates a distributed brute force alert", () => {
    const alert = AnomalyAlert.create({
      id: "alert-001",
      anomalyType: "distributed_brute_force",
      detectedAtMs: 1700000000000,
      details: {
        timeWindowMs: 60000,
        clientCount: 50,
        sourceAddresses: ["10.0.0.1", "10.0.0.2"],
      },
    });
    expect(alert.id).toBe("alert-001");
    expect(alert.anomalyType).toBe("distributed_brute_force");
    expect(alert.isCritical).toBe(true);
  });

  it("creates a volume anomaly alert (not critical)", () => {
    const alert = AnomalyAlert.create({
      id: "alert-002",
      anomalyType: "volume_anomaly",
      detectedAtMs: 1700000000000,
      details: {
        clientIdentifier: "alice-payment-service",
        baseline: 10,
        actual: 200,
        timeWindowMs: 3600000,
      },
    });
    expect(alert.anomalyType).toBe("volume_anomaly");
    expect(alert.isCritical).toBe(false);
  });

  it("mass lockout alert is critical", () => {
    const alert = AnomalyAlert.create({
      id: "alert-003",
      anomalyType: "mass_lockout",
      detectedAtMs: 1700000000000,
      details: { lockoutCount: 10, timeWindowMs: 300000 },
    });
    expect(alert.isCritical).toBe(true);
  });

  it("revoked client activity alert is critical", () => {
    const alert = AnomalyAlert.create({
      id: "alert-004",
      anomalyType: "revoked_client_activity",
      detectedAtMs: 1700000000000,
      details: {
        clientIdentifier: "alice",
        sourceAddress: "10.0.0.1",
      },
    });
    expect(alert.isCritical).toBe(true);
  });

  it("is immutable", () => {
    const alert = AnomalyAlert.create({
      id: "alert-005",
      anomalyType: "volume_anomaly",
      detectedAtMs: 1700000000000,
      details: { clientIdentifier: "alice" },
    });
    expect(Object.isFrozen(alert)).toBe(true);
    expect(Object.isFrozen(alert.details)).toBe(true);
  });

  it("preserves all detail fields", () => {
    const alert = AnomalyAlert.create({
      id: "alert-006",
      anomalyType: "distributed_brute_force",
      detectedAtMs: 1700000000000,
      details: {
        timeWindowMs: 60000,
        clientCount: 55,
        sourceAddresses: ["10.0.0.1", "10.0.0.2"],
      },
    });
    expect(alert.details.timeWindowMs).toBe(60000);
    expect(alert.details.clientCount).toBe(55);
    expect(alert.details.sourceAddresses).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(alert.detectedAtMs).toBe(1700000000000);
  });
});
