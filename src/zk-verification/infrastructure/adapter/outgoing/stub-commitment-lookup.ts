// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { CommitmentLookup, CommitmentInfo } from "../../../domain/port/outgoing/commitment-lookup.js";

export class StubCommitmentLookup implements CommitmentLookup {
  constructor(private result: CommitmentInfo | null = null) {}

  async findByClientIdentifier(): Promise<CommitmentInfo | null> {
    return this.result;
  }

  setResult(result: CommitmentInfo | null): void {
    this.result = result;
  }
}
