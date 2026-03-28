// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: normalizes the number of HTTP requests per authentication (R19-02 fix).
 *
 * Different tiers make different numbers of requests:
 *   Tier 0: 3 requests (enrollment-oprf → challenges → verify)
 *   Tier 1: 4 requests (vault-oprf → unseal-result → challenges → verify)
 *   Tier 2: 2 requests (challenges → verify)
 *
 * An observer counting TLS connections can distinguish tiers.
 *
 * Fix: ALL tiers make exactly 4 requests. Missing requests are filled
 * with dummy calls to a /v1/vault/ping endpoint that returns 200 + padding.
 */

const TARGET_REQUEST_COUNT = 4;

export class RequestNormalizer {
  constructor(
    private readonly sendDummy: () => Promise<void>,
  ) {}

  /**
   * After the real authentication requests are done, pad to TARGET_REQUEST_COUNT
   * by sending dummy requests.
   *
   * @param realRequestCount - how many real requests were made this session
   */
  async normalize(realRequestCount: number): Promise<void> {
    const padding = TARGET_REQUEST_COUNT - realRequestCount;
    for (let i = 0; i < padding; i++) {
      await this.sendDummy();
    }
  }
}
