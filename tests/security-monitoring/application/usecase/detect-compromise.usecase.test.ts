// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { DetectCompromiseUseCase } from "../../../../src/security-monitoring/application/usecase/detect-compromise.usecase.js";
import { CompromiseDetectionEngine } from "../../../../src/security-monitoring/domain/service/compromise-detection-engine.js";
import { CompromiseDetectionConfig } from "../../../../src/security-monitoring/domain/model/compromise-detection-config.js";
import { IpBinding } from "../../../../src/security-monitoring/domain/model/ip-binding.js";
import { GeoLocation } from "../../../../src/security-monitoring/domain/model/geo-location.js";
import type { IpBindingStore } from "../../../../src/security-monitoring/domain/port/outgoing/ip-binding-store.js";
import type { GeoIpLookup } from "../../../../src/security-monitoring/domain/port/outgoing/geo-ip-lookup.js";
import type { ClientSuspender } from "../../../../src/security-monitoring/domain/port/outgoing/client-suspender.js";
import type { EventPublisher, DomainEvent } from "../../../../src/security-monitoring/domain/port/outgoing/event-publisher.js";
import type { AuditLogStore } from "../../../../src/security-monitoring/domain/port/outgoing/audit-log-store.js";
import type { Clock } from "../../../../src/security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../../../src/security-monitoring/domain/port/outgoing/id-generator.js";
import type { AuditEntry } from "../../../../src/security-monitoring/domain/model/audit-entry.js";
import type { SuspensionReasonValue } from "../../../../src/security-monitoring/domain/model/suspension-reason.js";

// --- Test doubles ---

class StubIpBindingStore implements IpBindingStore {
  private bindings: IpBinding[] = [];

  async save(binding: IpBinding): Promise<void> {
    this.bindings.push(binding);
  }
  async findByClientIdentifier(clientIdentifier: string): Promise<readonly IpBinding[]> {
    return this.bindings.filter((b) => b.clientIdentifier === clientIdentifier);
  }
  async findLatestByClientIdentifier(clientIdentifier: string): Promise<IpBinding | null> {
    const filtered = this.bindings.filter((b) => b.clientIdentifier === clientIdentifier);
    return filtered.length > 0 ? filtered[filtered.length - 1] : null;
  }

  /** Test helper */
  addBinding(binding: IpBinding): void {
    this.bindings.push(binding);
  }
}

class StubGeoIpLookup implements GeoIpLookup {
  private locations = new Map<string, GeoLocation>();
  private shouldFail = false;

  async lookup(ip: string): Promise<GeoLocation | null> {
    if (this.shouldFail) {
      return null;
    }
    return this.locations.get(ip) ?? null;
  }

  setLocation(ip: string, location: GeoLocation): void {
    this.locations.set(ip, location);
  }

  setFailing(fail: boolean): void {
    this.shouldFail = fail;
  }
}

class StubClientSuspender implements ClientSuspender {
  readonly suspensions: Array<{ clientIdentifier: string; reason: SuspensionReasonValue }> = [];

  async suspend(clientIdentifier: string, reason: SuspensionReasonValue): Promise<boolean> {
    this.suspensions.push({ clientIdentifier, reason });
    return true;
  }
}

class SpyEventPublisher implements EventPublisher {
  readonly events: DomainEvent[] = [];
  async publish(event: DomainEvent): Promise<void> {
    this.events.push(event);
  }
}

class StubAuditLogStore implements AuditLogStore {
  readonly entries: AuditEntry[] = [];

  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }
  async findAll(): Promise<readonly AuditEntry[]> {
    return this.entries;
  }
  async count(): Promise<number> {
    return this.entries.length;
  }
}

class FakeClock implements Clock {
  private current = 1700000000000;
  nowMs(): number { return this.current; }
  set(ms: number): void { this.current = ms; }
}

class SequentialIdGenerator implements IdGenerator {
  private counter = 0;
  generate(): string { return `id-${++this.counter}`; }
}

// --- Tests ---

describe("DetectCompromiseUseCase", () => {
  let useCase: DetectCompromiseUseCase;
  let ipBindingStore: StubIpBindingStore;
  let geoIpLookup: StubGeoIpLookup;
  let clientSuspender: StubClientSuspender;
  let eventPublisher: SpyEventPublisher;
  let auditLogStore: StubAuditLogStore;
  let clock: FakeClock;
  let idGenerator: SequentialIdGenerator;
  let config: CompromiseDetectionConfig;

  beforeEach(() => {
    ipBindingStore = new StubIpBindingStore();
    geoIpLookup = new StubGeoIpLookup();
    clientSuspender = new StubClientSuspender();
    eventPublisher = new SpyEventPublisher();
    auditLogStore = new StubAuditLogStore();
    clock = new FakeClock();
    idGenerator = new SequentialIdGenerator();
    config = CompromiseDetectionConfig.defaults();

    useCase = new DetectCompromiseUseCase(
      new CompromiseDetectionEngine(),
      ipBindingStore,
      geoIpLookup,
      clientSuspender,
      eventPublisher,
      auditLogStore,
      clock,
      idGenerator,
      config,
    );
  });

  describe("first authentication (no previous IP)", () => {
    it("records IP binding and reports no anomaly", async () => {
      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "203.0.113.10",
        timestampMs: 1700000000000,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
      expect(result.reason).toBeNull();

      const bindings = await ipBindingStore.findByClientIdentifier("alice");
      expect(bindings).toHaveLength(1);
      expect(bindings[0].sourceIp).toBe("203.0.113.10");
    });
  });

  describe("same IP within window", () => {
    it("reports no anomaly", async () => {
      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000030000); // +30s

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "203.0.113.10",
        timestampMs: 1700000030000,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
    });
  });

  describe("concurrent session detection", () => {
    it("suspends client when different IPs within window", async () => {
      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000030000); // +30s

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000030000,
      });

      expect(result.anomalyDetected).toBe(true);
      expect(result.suspended).toBe(true);
      expect(result.reason).toBe("concurrent_session");
    });

    it("publishes ClientSuspended event with reason", async () => {
      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000030000);

      await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000030000,
      });

      expect(eventPublisher.events).toHaveLength(1);
      const event = eventPublisher.events[0];
      expect(event.eventType).toBe("ClientSuspended");
      expect((event as any).clientIdentifier).toBe("alice");
      expect((event as any).reason).toBe("concurrent_session");
    });

    it("calls client suspender", async () => {
      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000030000);

      await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000030000,
      });

      expect(clientSuspender.suspensions).toHaveLength(1);
      expect(clientSuspender.suspensions[0].clientIdentifier).toBe("alice");
      expect(clientSuspender.suspensions[0].reason).toBe("concurrent_session");
    });

    it("records audit entry on suspension", async () => {
      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000030000);

      await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000030000,
      });

      expect(auditLogStore.entries).toHaveLength(1);
      expect(auditLogStore.entries[0].eventType.value).toBe("auto_suspension");
    });

    it("does not suspend when different IPs outside window", async () => {
      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000120000); // +120s, outside 60s window

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000120000,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
      expect(clientSuspender.suspensions).toHaveLength(0);
    });
  });

  describe("geographic impossibility detection", () => {
    const paris = GeoLocation.create("203.0.113.10", 48.8566, 2.3522, "Paris", "FR");
    const tokyo = GeoLocation.create("198.51.100.42", 35.6762, 139.6503, "Tokyo", "JP");
    const london = GeoLocation.create("198.51.100.42", 51.5074, -0.1278, "London", "GB");

    it("suspends client on geographic impossibility", async () => {
      geoIpLookup.setLocation("203.0.113.10", paris);
      geoIpLookup.setLocation("198.51.100.42", tokyo);

      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000300000); // +5 min (outside 60s concurrent window)

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000300000,
      });

      expect(result.anomalyDetected).toBe(true);
      expect(result.suspended).toBe(true);
      expect(result.reason).toBe("geographic_impossibility");
    });

    it("does not suspend on possible travel", async () => {
      geoIpLookup.setLocation("203.0.113.10", paris);
      geoIpLookup.setLocation("198.51.100.42", london);

      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      const twoHoursMs = 2 * 60 * 60 * 1000;
      clock.set(1700000000000 + twoHoursMs);

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000000000 + twoHoursMs,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
    });

    it("skips geo detection when GeoIP lookup fails (graceful degradation)", async () => {
      geoIpLookup.setFailing(true);

      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000300000); // +5 min

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000300000,
      });

      // No geo detection, no concurrent (outside window), no suspension
      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
    });
  });

  describe("auto-suspend configuration", () => {
    it("does not suspend when autoSuspendOnAnomaly is false (alert-only mode)", async () => {
      const alertOnlyConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: true,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: false,
      });

      useCase = new DetectCompromiseUseCase(
        new CompromiseDetectionEngine(),
        ipBindingStore,
        geoIpLookup,
        clientSuspender,
        eventPublisher,
        auditLogStore,
        clock,
        idGenerator,
        alertOnlyConfig,
      );

      ipBindingStore.addBinding(
        IpBinding.create("alice", "203.0.113.10", 1700000000000),
      );
      clock.set(1700000030000);

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "198.51.100.42",
        timestampMs: 1700000030000,
      });

      expect(result.anomalyDetected).toBe(true);
      expect(result.suspended).toBe(false);
      expect(clientSuspender.suspensions).toHaveLength(0);
      expect(eventPublisher.events).toHaveLength(0);
    });
  });

  describe("IP binding disabled", () => {
    it("does not record IP binding when ipBindingEnabled is false", async () => {
      const noIpConfig = CompromiseDetectionConfig.create({
        ipBindingEnabled: false,
        concurrentSessionWindowMs: 60_000,
        geoSpeedThresholdKmH: 900,
        autoSuspendOnAnomaly: true,
      });

      useCase = new DetectCompromiseUseCase(
        new CompromiseDetectionEngine(),
        ipBindingStore,
        geoIpLookup,
        clientSuspender,
        eventPublisher,
        auditLogStore,
        clock,
        idGenerator,
        noIpConfig,
      );

      const result = await useCase.execute({
        clientIdentifier: "alice",
        sourceIp: "203.0.113.10",
        timestampMs: 1700000000000,
      });

      expect(result.anomalyDetected).toBe(false);
      expect(result.suspended).toBe(false);
      const bindings = await ipBindingStore.findByClientIdentifier("alice");
      expect(bindings).toHaveLength(0);
    });
  });
});
