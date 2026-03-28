// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { CommitmentRotated } from "../../../../src/client-registration/domain/event/commitment-rotated.js";

describe("CommitmentRotated", () => {
  it("exposes eventType, clientIdentifier, commitmentVersion, and occurredAt", () => {
    const event = new CommitmentRotated("client-1", 2);

    expect(event.eventType).toBe("CommitmentRotated");
    expect(event.clientIdentifier).toBe("client-1");
    expect(event.commitmentVersion).toBe(2);
    expect(event.occurredAt).toBeInstanceOf(Date);
  });

  it("implements DomainEvent interface", () => {
    const event = new CommitmentRotated("client-1", 2);

    expect(event.eventType).toBeDefined();
    expect(event.occurredAt).toBeDefined();
  });
});
