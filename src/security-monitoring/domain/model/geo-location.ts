// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Earth radius in kilometers for Haversine formula.
 */
const EARTH_RADIUS_KM = 6371;

/**
 * Value object representing a geographic location resolved from an IP address.
 * Immutable — frozen at creation.
 * Includes Haversine distance computation to another GeoLocation.
 */
export class GeoLocation {
  readonly ip: string;
  readonly latitude: number;
  readonly longitude: number;
  readonly city: string;
  readonly country: string;

  private constructor(
    ip: string,
    latitude: number,
    longitude: number,
    city: string,
    country: string,
  ) {
    this.ip = ip;
    this.latitude = latitude;
    this.longitude = longitude;
    this.city = city;
    this.country = country;
    Object.freeze(this);
  }

  static create(
    ip: string,
    latitude: number,
    longitude: number,
    city: string,
    country: string,
  ): GeoLocation {
    if (!ip || ip.trim().length === 0) {
      throw new Error("IP must not be empty");
    }
    if (latitude < -90 || latitude > 90) {
      throw new Error("Latitude must be between -90 and 90");
    }
    if (longitude < -180 || longitude > 180) {
      throw new Error("Longitude must be between -180 and 180");
    }
    return new GeoLocation(ip, latitude, longitude, city, country);
  }

  /**
   * Computes the great-circle distance to another GeoLocation using the Haversine formula.
   * Returns distance in kilometers.
   */
  distanceKm(other: GeoLocation): number {
    const lat1 = this.toRadians(this.latitude);
    const lat2 = this.toRadians(other.latitude);
    const deltaLat = this.toRadians(other.latitude - this.latitude);
    const deltaLon = this.toRadians(other.longitude - this.longitude);

    const a =
      Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
      Math.cos(lat1) * Math.cos(lat2) * Math.sin(deltaLon / 2) * Math.sin(deltaLon / 2);

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return EARTH_RADIUS_KM * c;
  }

  private toRadians(degrees: number): number {
    return (degrees * Math.PI) / 180;
  }
}
