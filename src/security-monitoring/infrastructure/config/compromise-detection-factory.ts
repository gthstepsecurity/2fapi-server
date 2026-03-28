// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { DetectCompromiseUseCase } from "../../application/usecase/detect-compromise.usecase.js";
import { CheckSuspensionStatusUseCase } from "../../application/usecase/check-suspension-status.usecase.js";
import { CompromiseDetectionEngine } from "../../domain/service/compromise-detection-engine.js";
import { CompromiseDetectionConfig } from "../../domain/model/compromise-detection-config.js";
import { InMemoryIpBindingStore } from "../adapter/outgoing/in-memory-ip-binding-store.js";
import type { GeoIpLookup } from "../../domain/port/outgoing/geo-ip-lookup.js";
import type { ClientSuspender } from "../../domain/port/outgoing/client-suspender.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { AuditLogStore } from "../../domain/port/outgoing/audit-log-store.js";
import type { Clock } from "../../domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { ClientStatusLookup } from "../../domain/port/outgoing/client-status-lookup.js";

export interface DetectCompromiseDeps {
  readonly geoIpLookup: GeoIpLookup;
  readonly clientSuspender: ClientSuspender;
  readonly eventPublisher: EventPublisher;
  readonly auditLogStore: AuditLogStore;
  readonly clock: Clock;
  readonly idGenerator: IdGenerator;
  readonly config?: CompromiseDetectionConfig;
}

export interface CheckSuspensionStatusDeps {
  readonly clientStatusLookup: ClientStatusLookup;
}

/**
 * Factory for creating compromise detection use cases with all dependencies wired.
 */
export class CompromiseDetectionFactory {
  static createDetectCompromiseUseCase(deps: DetectCompromiseDeps): DetectCompromiseUseCase {
    const engine = new CompromiseDetectionEngine();
    const ipBindingStore = new InMemoryIpBindingStore();
    const config = deps.config ?? CompromiseDetectionConfig.defaults();

    return new DetectCompromiseUseCase(
      engine,
      ipBindingStore,
      deps.geoIpLookup,
      deps.clientSuspender,
      deps.eventPublisher,
      deps.auditLogStore,
      deps.clock,
      deps.idGenerator,
      config,
    );
  }

  static createCheckSuspensionStatusUseCase(
    deps: CheckSuspensionStatusDeps,
  ): CheckSuspensionStatusUseCase {
    return new CheckSuspensionStatusUseCase(deps.clientStatusLookup);
  }
}
