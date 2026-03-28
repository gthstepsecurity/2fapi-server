// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { DetectCompromiseUseCase } from "../../src/security-monitoring/application/usecase/detect-compromise.usecase.js";
import { CheckSuspensionStatusUseCase } from "../../src/security-monitoring/application/usecase/check-suspension-status.usecase.js";
import { CompromiseDetectionEngine } from "../../src/security-monitoring/domain/service/compromise-detection-engine.js";
import { CompromiseDetectionConfig } from "../../src/security-monitoring/domain/model/compromise-detection-config.js";
import { GeoLocation } from "../../src/security-monitoring/domain/model/geo-location.js";
import { InMemoryIpBindingStore } from "../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-ip-binding-store.js";
import { StubGeoIpLookup } from "../../src/security-monitoring/infrastructure/adapter/outgoing/stub-geo-ip-lookup.js";
import { StubClientSuspender } from "../../src/security-monitoring/infrastructure/adapter/outgoing/stub-client-suspender.js";
import { InMemoryAuditLogStore } from "../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import type { EventPublisher, DomainEvent } from "../../src/security-monitoring/domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../src/security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../src/security-monitoring/domain/port/outgoing/id-generator.js";
import type { ClientStatusLookup } from "../../src/security-monitoring/domain/port/outgoing/client-status-lookup.js";

function createCapturingPublisher(): EventPublisher & { events: DomainEvent[] } {
  const pub: EventPublisher & { events: DomainEvent[] } = {
    events: [],
    async publish(event: DomainEvent): Promise<void> {
      pub.events.push(event);
    },
  };
  return pub;
}

function createIdGenerator(): IdGenerator {
  let counter = 0;
  return { generate: () => `id-${String(++counter).padStart(4, "0")}` };
}

describe("Compromise Detection — Acceptance Tests", () => {
  let currentTimeMs: number;
  let ipBindingStore: InMemoryIpBindingStore;
  let geoIpLookup: StubGeoIpLookup;
  let clientSuspender: StubClientSuspender;
  let eventPublisher: ReturnType<typeof createCapturingPublisher>;
  let auditLogStore: InMemoryAuditLogStore;
  let clock: Clock;
  let idGen: IdGenerator;
  let detectCompromise: DetectCompromiseUseCase;
  let clientStatuses: Map<string, "active" | "suspended" | "revoked">;
  let checkSuspensionStatus: CheckSuspensionStatusUseCase;

  beforeEach(() => {
    currentTimeMs = 1700000000000;
    ipBindingStore = new InMemoryIpBindingStore();
    geoIpLookup = new StubGeoIpLookup();
    clientSuspender = new StubClientSuspender();
    eventPublisher = createCapturingPublisher();
    auditLogStore = new InMemoryAuditLogStore();
    clock = { nowMs: () => currentTimeMs };
    idGen = createIdGenerator();
    clientStatuses = new Map([["alice-payment-service", "active"]]);

    const config = CompromiseDetectionConfig.defaults();

    detectCompromise = new DetectCompromiseUseCase(
      new CompromiseDetectionEngine(),
      ipBindingStore,
      geoIpLookup,
      clientSuspender,
      eventPublisher,
      auditLogStore,
      clock,
      idGen,
      config,
    );

    const clientStatusLookup: ClientStatusLookup = {
      async getStatus(clientIdentifier: string) {
        return clientStatuses.get(clientIdentifier) ?? null;
      },
    };
    checkSuspensionStatus = new CheckSuspensionStatusUseCase(clientStatusLookup);
  });

  describe("End-to-end: concurrent session detection -> suspension -> challenge refused", () => {
    it("auth from IP A -> auth from IP B -> suspension -> status check shows suspended", async () => {
      // Alice authenticates from IP A
      const firstAuth = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "203.0.113.10",
        timestampMs: currentTimeMs,
      });
      expect(firstAuth.anomalyDetected).toBe(false);
      expect(firstAuth.suspended).toBe(false);

      // 30 seconds later, Alice authenticates from IP B
      currentTimeMs += 30_000;
      const secondAuth = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "198.51.100.42",
        timestampMs: currentTimeMs,
      });

      // Anomaly detected and suspension triggered
      expect(secondAuth.anomalyDetected).toBe(true);
      expect(secondAuth.suspended).toBe(true);
      expect(secondAuth.reason).toBe("concurrent_session");

      // ClientSuspended event published
      expect(eventPublisher.events).toHaveLength(1);
      expect(eventPublisher.events[0].eventType).toBe("ClientSuspended");
      const event = eventPublisher.events[0] as any;
      expect(event.clientIdentifier).toBe("alice-payment-service");
      expect(event.reason).toBe("concurrent_session");

      // Client suspender was called
      expect(clientSuspender.suspensions).toHaveLength(1);
      expect(clientSuspender.suspensions[0].clientIdentifier).toBe("alice-payment-service");

      // Audit log records the suspension
      const entries = await auditLogStore.findAll();
      expect(entries).toHaveLength(1);
      expect(entries[0].eventType.value).toBe("auto_suspension");
      expect(entries[0].clientIdentifier).toBe("alice-payment-service");

      // Now simulate that the client is actually suspended in registry
      clientStatuses.set("alice-payment-service", "suspended");

      // Check suspension status
      const status = await checkSuspensionStatus.execute({
        clientIdentifier: "alice-payment-service",
      });
      expect(status.status).toBe("suspended");
    });
  });

  describe("End-to-end: geographic impossibility flow", () => {
    it("auth from Paris -> auth from Tokyo in 5 min -> suspension", async () => {
      const paris = GeoLocation.create("203.0.113.10", 48.8566, 2.3522, "Paris", "FR");
      const tokyo = GeoLocation.create("198.51.100.42", 35.6762, 139.6503, "Tokyo", "JP");
      geoIpLookup.setLocation("203.0.113.10", paris);
      geoIpLookup.setLocation("198.51.100.42", tokyo);

      // First auth from Paris
      await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "203.0.113.10",
        timestampMs: currentTimeMs,
      });

      // 5 minutes later, auth from Tokyo (beyond 60s concurrent window)
      currentTimeMs += 5 * 60 * 1000;
      const result = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "198.51.100.42",
        timestampMs: currentTimeMs,
      });

      expect(result.anomalyDetected).toBe(true);
      expect(result.suspended).toBe(true);
      expect(result.reason).toBe("geographic_impossibility");

      // Event published with location details
      const event = eventPublisher.events[0] as any;
      expect(event.reason).toBe("geographic_impossibility");
      expect(event.details.from).toEqual({ city: "Paris", country: "FR" });
      expect(event.details.to).toEqual({ city: "Tokyo", country: "JP" });
    });
  });

  describe("End-to-end: possible travel does not trigger suspension", () => {
    it("auth from Paris -> auth from London in 2 hours -> no suspension", async () => {
      const paris = GeoLocation.create("203.0.113.10", 48.8566, 2.3522, "Paris", "FR");
      const london = GeoLocation.create("198.51.100.42", 51.5074, -0.1278, "London", "GB");
      geoIpLookup.setLocation("203.0.113.10", paris);
      geoIpLookup.setLocation("198.51.100.42", london);

      await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "203.0.113.10",
        timestampMs: currentTimeMs,
      });

      currentTimeMs += 2 * 60 * 60 * 1000; // 2 hours
      const result = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "198.51.100.42",
        timestampMs: currentTimeMs,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
      expect(clientSuspender.suspensions).toHaveLength(0);
      expect(eventPublisher.events).toHaveLength(0);
    });
  });

  describe("Config disabled -> no suspension", () => {
    it("IP binding disabled means no detection", async () => {
      const noIpConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: false,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: true,
      });

      detectCompromise = new DetectCompromiseUseCase(
        new CompromiseDetectionEngine(),
        ipBindingStore,
        geoIpLookup,
        clientSuspender,
        eventPublisher,
        auditLogStore,
        clock,
        idGen,
        noIpConfig,
      );

      await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "203.0.113.10",
        timestampMs: currentTimeMs,
      });

      currentTimeMs += 30_000;
      const result = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "198.51.100.42",
        timestampMs: currentTimeMs,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
      expect(clientSuspender.suspensions).toHaveLength(0);
    });

    it("alert-only mode detects anomaly but does not suspend", async () => {
      const alertOnlyConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: false,
      });

      detectCompromise = new DetectCompromiseUseCase(
        new CompromiseDetectionEngine(),
        ipBindingStore,
        geoIpLookup,
        clientSuspender,
        eventPublisher,
        auditLogStore,
        clock,
        idGen,
        alertOnlyConfig,
      );

      await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "203.0.113.10",
        timestampMs: currentTimeMs,
      });

      currentTimeMs += 30_000;
      const result = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "198.51.100.42",
        timestampMs: currentTimeMs,
      });

      expect(result.anomalyDetected).toBe(true);
      expect(result.suspended).toBe(false);
      expect(clientSuspender.suspensions).toHaveLength(0);
      expect(eventPublisher.events).toHaveLength(0);
    });
  });

  describe("GeoIP lookup failure = graceful degradation", () => {
    it("auth proceeds without geo check when GeoIP fails", async () => {
      geoIpLookup.setFailing(true);

      await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "203.0.113.10",
        timestampMs: currentTimeMs,
      });

      // 5 minutes later, different IP — outside concurrent window, geo check skipped
      currentTimeMs += 5 * 60 * 1000;
      const result = await detectCompromise.execute({
        clientIdentifier: "alice-payment-service",
        sourceIp: "198.51.100.42",
        timestampMs: currentTimeMs,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
    });
  });

  describe("Suspended client response indistinguishable", () => {
    it("suspension status check returns same shape for suspended, revoked, unknown", async () => {
      clientStatuses.set("suspended-client", "suspended");
      clientStatuses.set("revoked-client", "revoked");

      const suspendedResult = await checkSuspensionStatus.execute({
        clientIdentifier: "suspended-client",
      });
      const revokedResult = await checkSuspensionStatus.execute({
        clientIdentifier: "revoked-client",
      });
      const unknownResult = await checkSuspensionStatus.execute({
        clientIdentifier: "unknown-client",
      });

      // Only suspended returns "suspended"; others return "active" (no info leak)
      expect(suspendedResult.status).toBe("suspended");
      expect(revokedResult.status).toBe("active");
      expect(unknownResult.status).toBe("active");

      // All responses have the same shape
      expect(Object.keys(suspendedResult)).toEqual(Object.keys(revokedResult));
      expect(Object.keys(suspendedResult)).toEqual(Object.keys(unknownResult));
    });
  });
});
