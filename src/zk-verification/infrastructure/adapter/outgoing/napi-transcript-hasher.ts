// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TranscriptHasher } from "../../../domain/port/outgoing/transcript-hasher.js";

/**
 * Contract for the native crypto module used by the transcript hasher.
 */
export interface NativeTranscriptModule {
  hashTranscript(data: Buffer): Buffer;
}

/**
 * Real implementation of TranscriptHasher using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Computes the Fiat-Shamir challenge from transcript bytes using
 * SHA-512 with reduction to a canonical Ristretto255 scalar.
 */
export class NapiTranscriptHasher implements TranscriptHasher {
  constructor(private readonly nativeModule: NativeTranscriptModule) {}

  hash(transcriptBytes: Uint8Array): Uint8Array {
    try {
      const result = this.nativeModule.hashTranscript(
        Buffer.from(transcriptBytes),
      );
      return new Uint8Array(result);
    } catch (error) {
      throw new Error(
        `Transcript hashing failed: native module error — ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
