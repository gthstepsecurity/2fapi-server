// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { EventPublisher, DomainEvent } from "../../../domain/port/outgoing/event-publisher.js";

export class NoopEventPublisher implements EventPublisher {
  async publish(_event: DomainEvent): Promise<void> {
    // No-op for testing and reference implementation
  }
}
