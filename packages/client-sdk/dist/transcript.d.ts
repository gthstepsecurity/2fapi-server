// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { TranscriptFields } from "@2fapi/protocol-spec";
/**
 * Build the canonical Fiat-Shamir transcript for the Sigma protocol.
 *
 * Serialization order: tag || G || H || C || A || clientId || nonce || channelBinding
 * ALL fields are length-prefixed with a 4-byte big-endian u32.
 *
 * This MUST match the server-side Transcript.build() exactly.
 */
export declare function buildTranscript(fields: TranscriptFields): Uint8Array;
//# sourceMappingURL=transcript.d.ts.map
