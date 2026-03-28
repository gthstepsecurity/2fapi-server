// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { GeoLocation } from "../../model/geo-location.js";

/**
 * Driven port for resolving an IP address to a geographic location.
 * Implementations may call external GeoIP services.
 * Returns null when the IP cannot be geolocated (graceful degradation).
 */
export interface GeoIpLookup {
  lookup(ip: string): Promise<GeoLocation | null>;
}
