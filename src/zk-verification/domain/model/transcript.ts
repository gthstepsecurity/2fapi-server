// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { DomainSeparationTag } from "./domain-separation-tag.js";

export interface TranscriptFields {
  readonly tag: DomainSeparationTag;
  readonly g: Uint8Array;
  readonly h: Uint8Array;
  readonly commitment: Uint8Array;
  readonly announcement: Uint8Array;
  readonly clientId: string;
  readonly nonce: Uint8Array;
  readonly channelBinding: Uint8Array;
}

/**
 * Fiat-Shamir transcript for the Sigma protocol.
 *
 * Canonical serialization order: tag || g || h || C || A || clientId || nonce || channelBinding
 * ALL variable-length fields are length-prefixed with a 4-byte big-endian u32
 * to prevent ambiguous concatenation attacks. While g, h, commitment, and
 * announcement are currently fixed at 32 bytes, nonce and channelBinding
 * could vary in future protocol versions, so they are also length-prefixed.
 *
 * NOTE: The client-side prover MUST zeroize the random scalars k_s and k_r
 * immediately after proof generation to prevent secret leakage.
 */
export class Transcript {
  private constructor(private readonly bytes: Uint8Array) {}

  static build(fields: TranscriptFields): Transcript {
    const encoder = new TextEncoder();
    const tagBytes = fields.tag.toBytes();
    const clientIdBytes = encoder.encode(fields.clientId);

    // Calculate total size — all fields are length-prefixed with 4-byte big-endian u32
    const totalSize =
      4 + tagBytes.length +         // length-prefixed tag
      4 + fields.g.length +         // length-prefixed g
      4 + fields.h.length +         // length-prefixed h
      4 + fields.commitment.length + // length-prefixed commitment
      4 + fields.announcement.length + // length-prefixed announcement
      4 + clientIdBytes.length +     // length-prefixed clientId
      4 + fields.nonce.length +      // length-prefixed nonce
      4 + fields.channelBinding.length; // length-prefixed channelBinding

    const buffer = new Uint8Array(totalSize);
    const view = new DataView(buffer.buffer);
    let offset = 0;

    // Helper: write a length-prefixed field
    const writeField = (data: Uint8Array): void => {
      view.setUint32(offset, data.length, false);
      offset += 4;
      buffer.set(data, offset);
      offset += data.length;
    };

    // tag
    writeField(tagBytes);

    // g
    writeField(fields.g);

    // h
    writeField(fields.h);

    // C (commitment)
    writeField(fields.commitment);

    // A (announcement)
    writeField(fields.announcement);

    // clientId
    writeField(clientIdBytes);

    // nonce
    writeField(fields.nonce);

    // channelBinding
    writeField(fields.channelBinding);

    return new Transcript(buffer);
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }
}
