// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TranscriptHasher } from "../../../domain/port/outgoing/transcript-hasher.js";

export class StubTranscriptHasher implements TranscriptHasher {
  private fixedHash: Uint8Array;

  constructor(fixedHash?: Uint8Array) {
    this.fixedHash = fixedHash ?? new Uint8Array(32).fill(0x42);
  }

  hash(): Uint8Array {
    return new Uint8Array(this.fixedHash);
  }

  setFixedHash(hash: Uint8Array): void {
    this.fixedHash = new Uint8Array(hash);
  }
}
