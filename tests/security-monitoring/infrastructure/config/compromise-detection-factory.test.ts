// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CompromiseDetectionFactory } from "../../../../src/security-monitoring/infrastructure/config/compromise-detection-factory.js";
import { CompromiseDetectionConfig } from "../../../../src/security-monitoring/domain/model/compromise-detection-config.js";
import type { GeoIpLookup } from "../../../../src/security-monitoring/domain/port/outgoing/geo-ip-lookup.js";
import type { ClientSuspender } from "../../../../src/security-monitoring/domain/port/outgoing/client-suspender.js";
import type { EventPublisher, DomainEvent } from "../../../../src/security-monitoring/domain/port/outgoing/event-publisher.js";
import type { AuditLogStore } from "../../../../src/security-monitoring/domain/port/outgoing/audit-log-store.js";
import type { Clock } from "../../../../src/security-monitoring/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../../../src/security-monitoring/domain/port/outgoing/id-generator.js";
import type { ClientStatusLookup } from "../../../../src/security-monitoring/domain/port/outgoing/client-status-lookup.js";
import { InMemoryAuditLogStore } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-audit-log-store.js";
import { StubGeoIpLookup } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/stub-geo-ip-lookup.js";
import { StubClientSuspender } from "../../../../src/security-monitoring/infrastructure/adapter/outgoing/stub-client-suspender.js";

describe("CompromiseDetectionFactory", () => {
  it("creates a DetectCompromiseUseCase with default config", () => {
    const deps = {
      geoIpLookup: new StubGeoIpLookup() as GeoIpLookup,
      clientSuspender: new StubClientSuspender() as ClientSuspender,
      eventPublisher: { events: [], async publish(_e: DomainEvent) {} } as EventPublisher,
      auditLogStore: new InMemoryAuditLogStore() as AuditLogStore,
      clock: { nowMs: () => Date.now() } as Clock,
      idGenerator: { generate: () => "id-1" } as IdGenerator,
    };

    const useCase = CompromiseDetectionFactory.createDetectCompromiseUseCase(deps);
    expect(useCase).toBeDefined();
  });

  it("creates a DetectCompromiseUseCase with custom config", () => {
    const config = CompromiseDetectionConfig.create({
      ipBindingEnabled: false,
      concurrentSessionWindowMs: 30_000,
      geoSpeedThresholdKmH: 500,
      autoSuspendOnAnomaly: false,
    });

    const deps = {
      geoIpLookup: new StubGeoIpLookup() as GeoIpLookup,
      clientSuspender: new StubClientSuspender() as ClientSuspender,
      eventPublisher: { async publish(_e: DomainEvent) {} } as EventPublisher,
      auditLogStore: new InMemoryAuditLogStore() as AuditLogStore,
      clock: { nowMs: () => Date.now() } as Clock,
      idGenerator: { generate: () => "id-1" } as IdGenerator,
      config,
    };

    const useCase = CompromiseDetectionFactory.createDetectCompromiseUseCase(deps);
    expect(useCase).toBeDefined();
  });

  it("creates a CheckSuspensionStatusUseCase", () => {
    const clientStatusLookup: ClientStatusLookup = {
      async getStatus() { return null; },
    };

    const useCase = CompromiseDetectionFactory.createCheckSuspensionStatusUseCase({
      clientStatusLookup,
    });
    expect(useCase).toBeDefined();
  });
});
