// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value Object representing the channel binding method used for
 * proof-of-possession token binding.
 *
 * Two methods are supported:
 * - "tls-exporter": TLS Exporter channel binding (RFC 9266) — preferred
 * - "dpop": DPoP proof-of-possession (RFC 9449) — fallback when TLS
 *           termination by CDN/proxy prevents TLS Exporter access
 */
export type ChannelBindingMethodType = "tls-exporter" | "dpop";

export interface AutoDetectInput {
  readonly tlsExporterAvailable: boolean;
  readonly dpopProofPresent: boolean;
}

export class ChannelBindingMethod {
  private constructor(readonly type: ChannelBindingMethodType) {}

  static tlsExporter(): ChannelBindingMethod {
    return new ChannelBindingMethod("tls-exporter");
  }

  static dpop(): ChannelBindingMethod {
    return new ChannelBindingMethod("dpop");
  }

  /**
   * Auto-detects the appropriate channel binding method.
   * TLS Exporter is always preferred when available.
   * Returns null when neither binding mechanism is available.
   */
  static autoDetect(input: AutoDetectInput): ChannelBindingMethod | null {
    if (input.tlsExporterAvailable) {
      return ChannelBindingMethod.tlsExporter();
    }
    if (input.dpopProofPresent) {
      return ChannelBindingMethod.dpop();
    }
    return null;
  }
}
