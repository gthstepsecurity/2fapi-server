// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { GeoIpLookup } from "../../../domain/port/outgoing/geo-ip-lookup.js";
import type { GeoLocation } from "../../../domain/model/geo-location.js";

/**
 * Stub implementation of GeoIpLookup for testing.
 * Returns preconfigured locations or null.
 */
export class StubGeoIpLookup implements GeoIpLookup {
  private readonly locations = new Map<string, GeoLocation>();
  private failing = false;

  async lookup(ip: string): Promise<GeoLocation | null> {
    if (this.failing) {
      return null;
    }
    return this.locations.get(ip) ?? null;
  }

  /** Test helper: configure a location for an IP. */
  setLocation(ip: string, location: GeoLocation): void {
    this.locations.set(ip, location);
  }

  /** Test helper: simulate GeoIP service failure. */
  setFailing(fail: boolean): void {
    this.failing = fail;
  }
}
