// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { GeoLocation } from "../../../../src/security-monitoring/domain/model/geo-location.js";

describe("GeoLocation", () => {
  it("creates a location with ip, latitude, longitude, city, and country", () => {
    const loc = GeoLocation.create("203.0.113.10", 48.8566, 2.3522, "Paris", "FR");

    expect(loc.ip).toBe("203.0.113.10");
    expect(loc.latitude).toBe(48.8566);
    expect(loc.longitude).toBe(2.3522);
    expect(loc.city).toBe("Paris");
    expect(loc.country).toBe("FR");
  });

  it("is immutable — frozen after creation", () => {
    const loc = GeoLocation.create("10.0.0.1", 0, 0, "Null Island", "XX");
    expect(Object.isFrozen(loc)).toBe(true);
  });

  it("rejects empty ip", () => {
    expect(() => GeoLocation.create("", 0, 0, "City", "XX")).toThrow(
      "IP must not be empty",
    );
  });

  it("rejects latitude below -90", () => {
    expect(() => GeoLocation.create("10.0.0.1", -91, 0, "City", "XX")).toThrow(
      "Latitude must be between -90 and 90",
    );
  });

  it("rejects latitude above 90", () => {
    expect(() => GeoLocation.create("10.0.0.1", 91, 0, "City", "XX")).toThrow(
      "Latitude must be between -90 and 90",
    );
  });

  it("rejects longitude below -180", () => {
    expect(() => GeoLocation.create("10.0.0.1", 0, -181, "City", "XX")).toThrow(
      "Longitude must be between -180 and 180",
    );
  });

  it("rejects longitude above 180", () => {
    expect(() => GeoLocation.create("10.0.0.1", 0, 181, "City", "XX")).toThrow(
      "Longitude must be between -180 and 180",
    );
  });

  describe("distanceKm (Haversine)", () => {
    it("returns 0 for same location", () => {
      const a = GeoLocation.create("1.1.1.1", 48.8566, 2.3522, "Paris", "FR");
      const b = GeoLocation.create("2.2.2.2", 48.8566, 2.3522, "Paris", "FR");
      expect(a.distanceKm(b)).toBe(0);
    });

    it("computes Paris to London (~340 km)", () => {
      const paris = GeoLocation.create("1.1.1.1", 48.8566, 2.3522, "Paris", "FR");
      const london = GeoLocation.create("2.2.2.2", 51.5074, -0.1278, "London", "GB");
      const distance = paris.distanceKm(london);
      expect(distance).toBeGreaterThan(330);
      expect(distance).toBeLessThan(350);
    });

    it("computes Paris to Tokyo (~9700 km)", () => {
      const paris = GeoLocation.create("1.1.1.1", 48.8566, 2.3522, "Paris", "FR");
      const tokyo = GeoLocation.create("2.2.2.2", 35.6762, 139.6503, "Tokyo", "JP");
      const distance = paris.distanceKm(tokyo);
      expect(distance).toBeGreaterThan(9600);
      expect(distance).toBeLessThan(9800);
    });

    it("computes New York to Sydney (~16000 km)", () => {
      const ny = GeoLocation.create("1.1.1.1", 40.7128, -74.006, "New York", "US");
      const sydney = GeoLocation.create("2.2.2.2", -33.8688, 151.2093, "Sydney", "AU");
      const distance = ny.distanceKm(sydney);
      expect(distance).toBeGreaterThan(15800);
      expect(distance).toBeLessThan(16200);
    });

    it("computes antipodal points (~20000 km)", () => {
      const north = GeoLocation.create("1.1.1.1", 90, 0, "North Pole", "XX");
      const south = GeoLocation.create("2.2.2.2", -90, 0, "South Pole", "XX");
      const distance = north.distanceKm(south);
      expect(distance).toBeGreaterThan(19900);
      expect(distance).toBeLessThan(20100);
    });
  });
});
