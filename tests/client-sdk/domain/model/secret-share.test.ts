// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { SecretShare } from "../../../../packages/client-sdk/src/domain/model/secret-share.js";

describe("SecretShare", () => {
  it("creates a client share with 32-byte scalars", () => {
    const share = SecretShare.create(
      new Uint8Array(32).fill(0x11),
      new Uint8Array(32).fill(0x22),
      "client",
    );
    expect(share.party).toBe("client");
    expect(share.shareS.length).toBe(32);
    expect(share.shareR.length).toBe(32);
  });

  it("creates a server share", () => {
    const share = SecretShare.create(
      new Uint8Array(32).fill(0xAA),
      new Uint8Array(32).fill(0xBB),
      "server",
    );
    expect(share.party).toBe("server");
  });

  it("rejects scalars with wrong length", () => {
    expect(() => SecretShare.create(
      new Uint8Array(16), new Uint8Array(32), "client",
    )).toThrow("32 bytes");
  });

  it("client and server shares are independent", () => {
    const client = SecretShare.create(
      new Uint8Array(32).fill(0x11),
      new Uint8Array(32).fill(0x22),
      "client",
    );
    const server = SecretShare.create(
      new Uint8Array(32).fill(0xAA),
      new Uint8Array(32).fill(0xBB),
      "server",
    );

    // Client share ≠ server share
    expect(Buffer.from(client.shareS).equals(Buffer.from(server.shareS))).toBe(false);
  });

  it("the full secret s = s1 + s2 is never computed in this model", () => {
    // This is a conceptual test: the SecretShare model does NOT provide
    // a method to combine shares. The combination happens IMPLICITLY
    // in the proof verification equation.
    const client = SecretShare.create(new Uint8Array(32).fill(0x11), new Uint8Array(32), "client");
    const server = SecretShare.create(new Uint8Array(32).fill(0xAA), new Uint8Array(32), "server");

    // No method exists to get the full secret
    expect((client as any).fullSecret).toBeUndefined();
    expect((server as any).fullSecret).toBeUndefined();
    // The only way to "combine" is via the Sigma proof verification:
    // z_s·G + z_r·H = A + c·C where z_s = z_s1 + z_s2
    // This addition happens on SCALARS, not on the share objects.
  });
});
