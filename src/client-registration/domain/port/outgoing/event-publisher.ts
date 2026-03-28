// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export interface DomainEvent {
  readonly eventType: string;
  readonly occurredAt: Date;
}

export interface EventPublisher {
  publish(event: DomainEvent): Promise<void>;
}
