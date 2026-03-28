// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { DOMAIN_SEPARATION_TAG } from "@2fapi/protocol-spec";
import type { TranscriptFields } from "@2fapi/protocol-spec";

/**
 * Build the canonical Fiat-Shamir transcript for the Sigma protocol.
 *
 * Serialization order: tag || G || H || C || A || clientId || nonce || channelBinding
 * ALL fields are length-prefixed with a 4-byte big-endian u32.
 *
 * This MUST match the server-side Transcript.build() exactly.
 */
export function buildTranscript(fields: TranscriptFields): Uint8Array {
  const encoder = new TextEncoder();
  const tagBytes = encoder.encode(fields.tag || DOMAIN_SEPARATION_TAG);
  const clientIdBytes = encoder.encode(fields.clientIdentifier);

  const totalSize =
    4 + tagBytes.length +
    4 + fields.generatorG.length +
    4 + fields.generatorH.length +
    4 + fields.commitment.length +
    4 + fields.announcement.length +
    4 + clientIdBytes.length +
    4 + fields.nonce.length +
    4 + fields.channelBinding.length;

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  const writeField = (data: Uint8Array): void => {
    view.setUint32(offset, data.length, false);
    offset += 4;
    buffer.set(data, offset);
    offset += data.length;
  };

  writeField(tagBytes);
  writeField(fields.generatorG);
  writeField(fields.generatorH);
  writeField(fields.commitment);
  writeField(fields.announcement);
  writeField(clientIdBytes);
  writeField(fields.nonce);
  writeField(fields.channelBinding);

  return buffer;
}
