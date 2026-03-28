// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { UniformHttpClient } from "../../../../../packages/client-sdk/src/infrastructure/adapter/outgoing/uniform-http-client.js";

// Capture what the fetch receives
interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  bodyLength: number;
  body: any;
}

function createCapturingFetch(): { fetch: typeof globalThis.fetch; captured: CapturedRequest[] } {
  const captured: CapturedRequest[] = [];

  const fetch = (async (url: string, init: RequestInit) => {
    const bodyStr = init.body as string;
    captured.push({
      url,
      method: init.method ?? "GET",
      headers: init.headers as Record<string, string>,
      bodyLength: bodyStr.length,
      body: JSON.parse(bodyStr),
    });

    // Return a valid mock envelope: 4-byte length + JSON + random padding
    const inner = JSON.stringify({ ok: true, status: "ready" });
    const buf = Buffer.alloc(480);
    buf.writeUInt32BE(inner.length, 0);
    Buffer.from(inner).copy(buf, 4);
    const mockResponse = JSON.stringify({ data: buf.toString("hex") });
    return {
      ok: true,
      status: 200,
      json: async () => JSON.parse(mockResponse),
    };
  }) as unknown as typeof globalThis.fetch;

  return { fetch, captured };
}

describe("UniformHttpClient", () => {
  // --- R23-01: Single endpoint ---

  it("all operations go to the same URL", async () => {
    const { fetch, captured } = createCapturingFetch();
    const client = new UniformHttpClient("https://api.acme.com", fetch);

    await client.send({ op: "seal", client_id: "c1", device_id: "d1" });
    await client.send({ op: "evaluate", client_id: "c1", device_id: "d1", blinded_point: "AAAA" });
    await client.send({ op: "unseal_result", client_id: "c1", device_id: "d1", eval_nonce: "nn", status: "success" });
    await client.sendDummy();

    for (const req of captured) {
      expect(req.url).toBe("https://api.acme.com/v1/vault");
    }
  });

  // --- R23-02: Fixed body size ---

  it("all operations produce identical body length", async () => {
    const { fetch, captured } = createCapturingFetch();
    const client = new UniformHttpClient("https://api.acme.com", fetch);

    await client.send({ op: "seal", client_id: "c1", device_id: "d1" });
    await client.send({ op: "evaluate", client_id: "c1", device_id: "d1", blinded_point: "A".repeat(44) });
    await client.send({ op: "unseal_result", client_id: "c1", device_id: "d1", eval_nonce: "n".repeat(64), status: "failure" });
    await client.sendDummy();

    const sizes = captured.map(r => r.bodyLength);
    // ALL body sizes must be identical
    expect(new Set(sizes).size).toBe(1);
  });

  it("body contains 960-char hex data field", async () => {
    const { fetch, captured } = createCapturingFetch();
    const client = new UniformHttpClient("https://api.acme.com", fetch);

    await client.send({ op: "seal", client_id: "c1", device_id: "d1" });

    expect(captured[0]!.body.data).toBeDefined();
    expect(captured[0]!.body.data.length).toBe(960); // 480 bytes × 2 hex
  });

  // --- R23-04: Authorization header always present ---

  it("all requests include Authorization header", async () => {
    const { fetch, captured } = createCapturingFetch();
    const client = new UniformHttpClient("https://api.acme.com", fetch);

    await client.send({ op: "seal", client_id: "c1", device_id: "d1" }, "real-jwt-token");
    await client.send({ op: "evaluate", client_id: "c1", device_id: "d1", blinded_point: "AA" });
    await client.sendDummy();

    for (const req of captured) {
      expect(req.headers["Authorization"]).toBeDefined();
      expect(req.headers["Authorization"]!.startsWith("Bearer ")).toBe(true);
    }
  });

  it("Authorization header has fixed length (real or dummy)", async () => {
    const { fetch, captured } = createCapturingFetch();
    const client = new UniformHttpClient("https://api.acme.com", fetch);

    await client.send({ op: "seal", client_id: "c1", device_id: "d1" }, "short-jwt");
    await client.send({ op: "evaluate", client_id: "c1", device_id: "d1", blinded_point: "AA" });

    const lengths = captured.map(r => r.headers["Authorization"]!.length);
    // All Authorization headers must be the same length
    expect(new Set(lengths).size).toBe(1);
  });

  // --- R23-03: client_id length hidden inside envelope ---

  it("different client_id lengths produce identical body size", async () => {
    const { fetch, captured } = createCapturingFetch();
    const client = new UniformHttpClient("https://api.acme.com", fetch);

    await client.send({ op: "seal", client_id: "a@b.com", device_id: "d1" });
    await client.send({ op: "seal", client_id: "alice.wonderland@megacorporation.example.com", device_id: "d1" });

    expect(captured[0]!.bodyLength).toBe(captured[1]!.bodyLength);
  });

  // --- Full indistinguishability ---

  it("4 requests for Tier 0 and 4 requests for Tier 1 are byte-identical in structure", async () => {
    const { fetch: fetch0, captured: tier0 } = createCapturingFetch();
    const { fetch: fetch1, captured: tier1 } = createCapturingFetch();

    const client0 = new UniformHttpClient("https://api.acme.com", fetch0);
    const client1 = new UniformHttpClient("https://api.acme.com", fetch1);

    // Tier 0: seal + evaluate + unseal-result + dummy
    await client0.send({ op: "seal", client_id: "alice", device_id: "d1" });
    await client0.send({ op: "evaluate", client_id: "alice", device_id: "d1", blinded_point: "BB" });
    await client0.send({ op: "unseal_result", client_id: "alice", device_id: "d1", eval_nonce: "nn", status: "success" });
    await client0.sendDummy();

    // Tier 1: evaluate + unseal-result + challenge-equivalent + verify-equivalent
    await client1.send({ op: "evaluate", client_id: "bob", device_id: "d2", blinded_point: "CC" });
    await client1.send({ op: "unseal_result", client_id: "bob", device_id: "d2", eval_nonce: "mm", status: "failure" });
    await client1.send({ op: "seal", client_id: "bob", device_id: "d2" });
    await client1.sendDummy();

    // Same number of requests
    expect(tier0.length).toBe(4);
    expect(tier1.length).toBe(4);

    // Same body sizes for every request
    for (let i = 0; i < 4; i++) {
      expect(tier0[i]!.bodyLength).toBe(tier1[i]!.bodyLength);
    }

    // Same URLs
    for (let i = 0; i < 4; i++) {
      expect(tier0[i]!.url).toBe(tier1[i]!.url);
    }

    // Same Authorization header lengths
    for (let i = 0; i < 4; i++) {
      expect(tier0[i]!.headers["Authorization"]!.length).toBe(tier1[i]!.headers["Authorization"]!.length);
    }
  });
});
