// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Computes the Fiat-Shamir challenge from the transcript bytes.
 * The output is a canonical scalar (reduced modulo group order l).
 */
export interface TranscriptHasher {
  hash(transcriptBytes: Uint8Array): Uint8Array;
}
