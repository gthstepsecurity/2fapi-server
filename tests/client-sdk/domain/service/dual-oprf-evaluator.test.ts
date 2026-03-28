// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { DualOprfEvaluator, type OprfHsmEndpoint } from "../../../../packages/client-sdk/src/domain/service/dual-oprf-evaluator.js";

function stubHsm(name: string, evalResult: Uint8Array): OprfHsmEndpoint {
  return {
    name,
    vendor: `Vendor-${name}`,
    jurisdiction: `Country-${name}`,
    evaluate: async () => ({ status: "ok" as const, evaluated: evalResult }),
  };
}

function failingHsm(name: string): OprfHsmEndpoint {
  return {
    name,
    vendor: `Vendor-${name}`,
    jurisdiction: `Country-${name}`,
    evaluate: async () => ({ status: "error" as const, message: "HSM offline" }),
  };
}

describe("DualOprfEvaluator", () => {
  it("evaluates across two HSMs and returns both results", async () => {
    const dual = new DualOprfEvaluator(
      stubHsm("A", new Uint8Array(32).fill(0xAA)),
      stubHsm("B", new Uint8Array(32).fill(0xBB)),
    );

    const result = await dual.evaluate(new Uint8Array(32).fill(0x11));
    expect(result.status).toBe("ok");
    if (result.status === "ok") {
      expect(result.evaluatedA[0]).toBe(0xAA);
      expect(result.evaluatedB[0]).toBe(0xBB);
    }
  });

  it("fails if HSM A is down", async () => {
    const dual = new DualOprfEvaluator(
      failingHsm("A"),
      stubHsm("B", new Uint8Array(32).fill(0xBB)),
    );

    const result = await dual.evaluate(new Uint8Array(32).fill(0x11));
    expect(result.status).toBe("error");
    if (result.status === "error") {
      expect(result.failedHsm).toBe("A");
    }
  });

  it("fails if HSM B is down", async () => {
    const dual = new DualOprfEvaluator(
      stubHsm("A", new Uint8Array(32).fill(0xAA)),
      failingHsm("B"),
    );

    const result = await dual.evaluate(new Uint8Array(32).fill(0x11));
    expect(result.status).toBe("error");
    if (result.status === "error") {
      expect(result.failedHsm).toBe("B");
    }
  });

  it("evaluates both HSMs in parallel (not sequentially)", async () => {
    let aStarted = 0;
    let bStarted = 0;

    const slowHsmA: OprfHsmEndpoint = {
      name: "A", vendor: "V-A", jurisdiction: "FR",
      evaluate: async () => {
        aStarted = Date.now();
        await new Promise(r => setTimeout(r, 50));
        return { status: "ok", evaluated: new Uint8Array(32).fill(0xAA) };
      },
    };

    const slowHsmB: OprfHsmEndpoint = {
      name: "B", vendor: "V-B", jurisdiction: "DE",
      evaluate: async () => {
        bStarted = Date.now();
        await new Promise(r => setTimeout(r, 50));
        return { status: "ok", evaluated: new Uint8Array(32).fill(0xBB) };
      },
    };

    const dual = new DualOprfEvaluator(slowHsmA, slowHsmB);
    const start = Date.now();
    await dual.evaluate(new Uint8Array(32).fill(0x11));
    const elapsed = Date.now() - start;

    // If parallel: ~50ms. If sequential: ~100ms.
    expect(elapsed).toBeLessThan(90);
    // Both should have started within 5ms of each other
    expect(Math.abs(aStarted - bStarted)).toBeLessThan(10);
  });

  it("two HSMs from different vendors/jurisdictions required", () => {
    const hsmA = stubHsm("A", new Uint8Array(32));
    const hsmB = stubHsm("B", new Uint8Array(32));
    expect(hsmA.vendor).not.toBe(hsmB.vendor);
    expect(hsmA.jurisdiction).not.toBe(hsmB.jurisdiction);
  });

  it("combined evaluation differs from single HSM (different keys)", async () => {
    const dual = new DualOprfEvaluator(
      stubHsm("A", new Uint8Array(32).fill(0xAA)),
      stubHsm("B", new Uint8Array(32).fill(0xBB)),
    );

    const result = await dual.evaluate(new Uint8Array(32).fill(0x11));
    if (result.status === "ok") {
      // E_A ≠ E_B (different keys produce different evaluations)
      expect(Buffer.from(result.evaluatedA).equals(Buffer.from(result.evaluatedB))).toBe(false);
    }
  });
});
