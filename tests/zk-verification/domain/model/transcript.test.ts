// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Transcript } from "../../../../src/zk-verification/domain/model/transcript.js";
import { DomainSeparationTag } from "../../../../src/zk-verification/domain/model/domain-separation-tag.js";

describe("Transcript", () => {
  it("should build a transcript with length-prefixed fields in canonical order", () => {
    const tag = DomainSeparationTag.protocol();
    const g = new Uint8Array(32).fill(0x01);
    const h = new Uint8Array(32).fill(0x02);
    const commitment = new Uint8Array(32).fill(0x03);
    const announcement = new Uint8Array(32).fill(0x04);
    const clientId = "alice";
    const nonce = new Uint8Array(24).fill(0x05);
    const channelBinding = new Uint8Array(32).fill(0x06);

    const transcript = Transcript.build({
      tag, g, h, commitment, announcement, clientId, nonce, channelBinding,
    });

    const bytes = transcript.toBytes();
    expect(bytes.length).toBeGreaterThan(0);
  });

  it("should produce deterministic output for the same inputs", () => {
    const params = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      clientId: "alice",
      nonce: new Uint8Array(24).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    };

    const t1 = Transcript.build(params);
    const t2 = Transcript.build(params);

    expect(t1.toBytes()).toEqual(t2.toBytes());
  });

  it("should produce different output for different client identifiers", () => {
    const base = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      nonce: new Uint8Array(24).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    };

    const t1 = Transcript.build({ ...base, clientId: "alice" });
    const t2 = Transcript.build({ ...base, clientId: "bob" });

    expect(t1.toBytes()).not.toEqual(t2.toBytes());
  });

  it("should use length-prefixing to prevent ambiguous concatenation", () => {
    const base = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      nonce: new Uint8Array(24).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    };

    // "ab" + "cd" must differ from "a" + "bcd"
    // This is guaranteed by length-prefixing each variable-length field
    const t1 = Transcript.build({ ...base, clientId: "ab" });
    const t2 = Transcript.build({ ...base, clientId: "a" });

    expect(t1.toBytes()).not.toEqual(t2.toBytes());
    // "ab" is 1 byte longer than "a", so t1 is 1 byte longer
    expect(t1.toBytes().length).toBe(t2.toBytes().length + 1);
  });

  it("should length-prefix ALL fields including nonce and channelBinding", () => {
    const base = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      clientId: "alice",
    };

    // Different nonce lengths produce different transcripts and sizes
    const t1 = Transcript.build({
      ...base,
      nonce: new Uint8Array(24).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    });
    const t2 = Transcript.build({
      ...base,
      nonce: new Uint8Array(16).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    });

    expect(t1.toBytes()).not.toEqual(t2.toBytes());
    // 8 bytes difference in nonce length
    expect(t1.toBytes().length).toBe(t2.toBytes().length + 8);
  });

  it("should produce different transcripts for different nonces (injection resistance)", () => {
    const base = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      clientId: "alice",
      channelBinding: new Uint8Array(32).fill(0x06),
    };

    const t1 = Transcript.build({ ...base, nonce: new Uint8Array(24).fill(0x05) });
    const t2 = Transcript.build({ ...base, nonce: new Uint8Array(24).fill(0xff) });

    expect(t1.toBytes()).not.toEqual(t2.toBytes());
  });

  it("should produce different transcripts for different channelBindings (injection resistance)", () => {
    const base = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      clientId: "alice",
      nonce: new Uint8Array(24).fill(0x05),
    };

    const t1 = Transcript.build({ ...base, channelBinding: new Uint8Array(32).fill(0x06) });
    const t2 = Transcript.build({ ...base, channelBinding: new Uint8Array(32).fill(0xff) });

    expect(t1.toBytes()).not.toEqual(t2.toBytes());
  });

  it("should produce unique transcripts for any single-field variation (property-based injection test)", () => {
    // Verify that changing ANY single field produces a different transcript.
    // This is a lightweight property-based test: for each field, we vary it
    // while keeping all others constant, ensuring transcript injection resistance.
    const baseFields = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      announcement: new Uint8Array(32).fill(0x04),
      clientId: "alice",
      nonce: new Uint8Array(24).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    };

    const baseTranscript = Transcript.build(baseFields).toBytes();

    const variations: Array<Partial<typeof baseFields>> = [
      { g: new Uint8Array(32).fill(0xff) },
      { h: new Uint8Array(32).fill(0xff) },
      { commitment: new Uint8Array(32).fill(0xff) },
      { announcement: new Uint8Array(32).fill(0xff) },
      { clientId: "bob" },
      { nonce: new Uint8Array(24).fill(0xff) },
      { channelBinding: new Uint8Array(32).fill(0xff) },
    ];

    for (const variation of variations) {
      const variedTranscript = Transcript.build({ ...baseFields, ...variation }).toBytes();
      expect(variedTranscript).not.toEqual(baseTranscript);
    }
  });

  it("should include the announcement A in the transcript (Fiat-Shamir binding)", () => {
    const base = {
      tag: DomainSeparationTag.protocol(),
      g: new Uint8Array(32).fill(0x01),
      h: new Uint8Array(32).fill(0x02),
      commitment: new Uint8Array(32).fill(0x03),
      clientId: "alice",
      nonce: new Uint8Array(24).fill(0x05),
      channelBinding: new Uint8Array(32).fill(0x06),
    };

    const t1 = Transcript.build({ ...base, announcement: new Uint8Array(32).fill(0x04) });
    const t2 = Transcript.build({ ...base, announcement: new Uint8Array(32).fill(0xff) });

    expect(t1.toBytes()).not.toEqual(t2.toBytes());
  });

  it("should use big-endian (false) for length prefix encoding", () => {
    // Kill mutant: `view.setUint32(offset, data.length, true)` instead of `false`
    // With little-endian, a 32-byte field would have length prefix [32,0,0,0]
    // With big-endian, it would have [0,0,0,32]
    const tag = DomainSeparationTag.protocol();
    const g = new Uint8Array(32).fill(0x01);
    const h = new Uint8Array(32).fill(0x02);
    const commitment = new Uint8Array(32).fill(0x03);
    const announcement = new Uint8Array(32).fill(0x04);
    const clientId = "alice";
    const nonce = new Uint8Array(24).fill(0x05);
    const channelBinding = new Uint8Array(32).fill(0x06);

    const transcript = Transcript.build({
      tag, g, h, commitment, announcement, clientId, nonce, channelBinding,
    });

    const bytes = transcript.toBytes();
    // The first field is the tag. Read the length prefix (first 4 bytes).
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const tagLength = view.getUint32(0, false); // read as big-endian
    // Tag "2FApi-v1.0-Sigma" is 16 bytes
    expect(tagLength).toBe(16);

    // If it were little-endian, reading as big-endian would give wrong result
    // Verify the second field (g) length prefix at offset 4 + 16 = 20
    const gLength = view.getUint32(20, false);
    expect(gLength).toBe(32);
  });
});
