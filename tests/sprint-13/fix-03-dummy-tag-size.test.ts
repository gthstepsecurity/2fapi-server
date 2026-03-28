// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DomainSeparationTag } from "../../src/zk-verification/domain/model/domain-separation-tag.js";
import { Transcript } from "../../src/zk-verification/domain/model/transcript.js";

describe("FIX 3 — Dummy Domain Separation Tag Size", () => {
  const baseFields = {
    g: new Uint8Array(32).fill(0x01),
    h: new Uint8Array(32).fill(0x02),
    commitment: new Uint8Array(32).fill(0xaa),
    announcement: new Uint8Array(32).fill(0xbb),
    clientId: "alice-payment-service",
    nonce: new Uint8Array(24).fill(0xcc),
    channelBinding: new Uint8Array(32).fill(0xdd),
  };

  it("dummy tag '2FApi-v1.0-Sigma' produces same transcript byte length as real tag", () => {
    const realTag = DomainSeparationTag.protocol();
    const dummyTag = DomainSeparationTag.fromString("2FApi-v1.0-Sigma");

    const realTranscript = Transcript.build({ tag: realTag, ...baseFields });
    const dummyTranscript = Transcript.build({ tag: dummyTag, ...baseFields });

    expect(dummyTranscript.toBytes().length).toBe(realTranscript.toBytes().length);
  });

  it("old dummy tag 'dummy' would produce a DIFFERENT transcript byte length", () => {
    const realTag = DomainSeparationTag.protocol();
    const oldDummyTag = DomainSeparationTag.fromString("dummy");

    const realTranscript = Transcript.build({ tag: realTag, ...baseFields });
    const oldDummyTranscript = Transcript.build({ tag: oldDummyTag, ...baseFields });

    // "dummy" is 5 bytes, "2FApi-v1.0-Sigma" is 16 bytes — different lengths
    expect(oldDummyTranscript.toBytes().length).not.toBe(realTranscript.toBytes().length);
  });

  it("the protocol tag constant is '2FApi-v1.0-Sigma'", () => {
    const protocolTag = DomainSeparationTag.protocol();
    expect(protocolTag.toBytes().length).toBe(16); // "2FApi-v1.0-Sigma" = 16 bytes
  });
});
