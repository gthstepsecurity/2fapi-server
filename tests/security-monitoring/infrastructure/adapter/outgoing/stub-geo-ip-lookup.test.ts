// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { StubGeoIpLookup } from "../../../../../src/security-monitoring/infrastructure/adapter/outgoing/stub-geo-ip-lookup.js";
import { GeoLocation } from "../../../../../src/security-monitoring/domain/model/geo-location.js";

describe("StubGeoIpLookup", () => {
  it("returns null for unknown IP", async () => {
    const stub = new StubGeoIpLookup();
    const result = await stub.lookup("1.2.3.4");
    expect(result).toBeNull();
  });

  it("returns configured location for known IP", async () => {
    const stub = new StubGeoIpLookup();
    const paris = GeoLocation.create("203.0.113.10", 48.8566, 2.3522, "Paris", "FR");
    stub.setLocation("203.0.113.10", paris);

    const result = await stub.lookup("203.0.113.10");
    expect(result).not.toBeNull();
    expect(result!.city).toBe("Paris");
  });

  it("returns null when set to failing mode", async () => {
    const stub = new StubGeoIpLookup();
    const paris = GeoLocation.create("203.0.113.10", 48.8566, 2.3522, "Paris", "FR");
    stub.setLocation("203.0.113.10", paris);
    stub.setFailing(true);

    const result = await stub.lookup("203.0.113.10");
    expect(result).toBeNull();
  });
});
