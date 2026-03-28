// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Environment detection and configuration loading for 2FApi.
 *
 * Configuration is loaded from environment variables.
 * Production requires PostgreSQL, Redis, and EdDSA key configuration.
 * Development uses in-memory adapters with permissive defaults.
 */

export type Environment = "development" | "test" | "production";

/**
 * Detects the current environment from TWOFAPI_ENV or NODE_ENV.
 * Falls back to "development" if neither is set.
 */
export function detectEnvironment(): Environment {
  const env = process.env["TWOFAPI_ENV"] || process.env["NODE_ENV"] || "development";
  if (env === "production") return "production";
  if (env === "test") return "test";
  return "development";
}

export interface DatabaseConfig {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
  readonly ssl?: boolean;
}

export interface RedisConfig {
  readonly host: string;
  readonly port: number;
  readonly password?: string;
  readonly tls?: boolean;
}

export interface CryptoConfig {
  readonly eddsaPrivateKeyPath?: string;
  readonly eddsaPrivateKeyHex?: string;
}

export interface TwoFApiConfig {
  readonly environment: Environment;
  readonly database: DatabaseConfig;
  readonly redis: RedisConfig;
  readonly crypto: CryptoConfig;
  readonly server: {
    readonly port: number;
    readonly channelBindingMode: "strict" | "permissive";
  };
  readonly rateLimiting: {
    readonly globalMaxRequests: number;
    readonly globalWindowMs: number;
    readonly perIpMaxRequests: number;
    readonly perIpWindowMs: number;
  };
  readonly lockout: {
    readonly threshold: number;
    readonly durationMs: number;
    readonly backoffMultiplier: number;
  };
  readonly recovery: {
    readonly wordCount: 12 | 18 | 24;
    readonly argon2Memory: number;
    readonly argon2Iterations: number;
    readonly argon2Parallelism: number;
    readonly maxAttempts: number;
    readonly mode: "phrase_only" | "external_only" | "phrase_and_external";
  };
}

/**
 * Reads a required environment variable, throwing if missing in production.
 */
function requireEnv(name: string, environment: Environment): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    if (environment === "production") {
      throw new Error(`Missing required environment variable: ${name}`);
    }
    return "";
  }
  return value;
}

/**
 * Reads an optional environment variable with a default fallback.
 */
function optionalEnv(name: string, defaultValue: string): string {
  return process.env[name] ?? defaultValue;
}

/**
 * Parses an integer from an environment variable with a default.
 */
function intEnv(name: string, defaultValue: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return defaultValue;
  const parsed = parseInt(raw, 10);
  if (isNaN(parsed)) {
    throw new Error(`Invalid integer for ${name}: ${raw}`);
  }
  return parsed;
}

/**
 * Parses a boolean from an environment variable.
 */
function boolEnv(name: string, defaultValue: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return defaultValue;
  return raw === "true" || raw === "1";
}

/**
 * Loads the full 2FApi configuration from environment variables.
 *
 * Environment variables:
 * - TWOFAPI_ENV / NODE_ENV: "production" | "test" | "development"
 * - POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
 * - REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
 * - EDDSA_PRIVATE_KEY_PATH, EDDSA_PRIVATE_KEY_HEX
 * - SERVER_PORT, CHANNEL_BINDING_MODE
 * - RATE_LIMIT_GLOBAL_MAX, RATE_LIMIT_GLOBAL_WINDOW_MS
 * - RATE_LIMIT_IP_MAX, RATE_LIMIT_IP_WINDOW_MS
 * - LOCKOUT_THRESHOLD, LOCKOUT_DURATION_MS, LOCKOUT_BACKOFF_MULTIPLIER
 * - RECOVERY_WORD_COUNT, RECOVERY_ARGON2_MEMORY, RECOVERY_ARGON2_ITERATIONS
 * - RECOVERY_ARGON2_PARALLELISM, RECOVERY_MAX_ATTEMPTS, RECOVERY_MODE
 */
export function loadConfigFromEnv(): TwoFApiConfig {
  const environment = detectEnvironment();

  const wordCountRaw = intEnv("RECOVERY_WORD_COUNT", 12);
  if (wordCountRaw !== 12 && wordCountRaw !== 18 && wordCountRaw !== 24) {
    throw new Error("RECOVERY_WORD_COUNT must be 12, 18, or 24");
  }
  const wordCount = wordCountRaw as 12 | 18 | 24;

  const modeRaw = optionalEnv("RECOVERY_MODE", "phrase_and_external");
  if (
    modeRaw !== "phrase_only" &&
    modeRaw !== "external_only" &&
    modeRaw !== "phrase_and_external"
  ) {
    throw new Error("RECOVERY_MODE must be phrase_only, external_only, or phrase_and_external");
  }
  const mode = modeRaw as "phrase_only" | "external_only" | "phrase_and_external";

  const channelBindingRaw = optionalEnv("CHANNEL_BINDING_MODE", "strict");
  if (channelBindingRaw !== "strict" && channelBindingRaw !== "permissive") {
    throw new Error("CHANNEL_BINDING_MODE must be strict or permissive");
  }
  const channelBindingMode = channelBindingRaw as "strict" | "permissive";

  return {
    environment,
    database: {
      host: optionalEnv("POSTGRES_HOST", "localhost"),
      port: intEnv("POSTGRES_PORT", 5432),
      database: optionalEnv("POSTGRES_DB", "twofapi"),
      user: optionalEnv("POSTGRES_USER", "twofapi"),
      password: requireEnv("POSTGRES_PASSWORD", environment),
      ssl: boolEnv("POSTGRES_SSL", false),
    },
    redis: {
      host: optionalEnv("REDIS_HOST", "localhost"),
      port: intEnv("REDIS_PORT", 6379),
      ...(process.env["REDIS_PASSWORD"] ? { password: process.env["REDIS_PASSWORD"] } : {}),
      tls: boolEnv("REDIS_TLS", false),
    },
    crypto: {
      ...(process.env["EDDSA_PRIVATE_KEY_PATH"] ? { eddsaPrivateKeyPath: process.env["EDDSA_PRIVATE_KEY_PATH"] } : {}),
      ...(process.env["EDDSA_PRIVATE_KEY_HEX"] ? { eddsaPrivateKeyHex: process.env["EDDSA_PRIVATE_KEY_HEX"] } : {}),
    },
    server: {
      port: intEnv("SERVER_PORT", 3000),
      channelBindingMode,
    },
    rateLimiting: {
      globalMaxRequests: intEnv("RATE_LIMIT_GLOBAL_MAX", 1000),
      globalWindowMs: intEnv("RATE_LIMIT_GLOBAL_WINDOW_MS", 1000),
      perIpMaxRequests: intEnv("RATE_LIMIT_IP_MAX", 100),
      perIpWindowMs: intEnv("RATE_LIMIT_IP_WINDOW_MS", 1000),
    },
    lockout: {
      threshold: intEnv("LOCKOUT_THRESHOLD", 3),
      durationMs: intEnv("LOCKOUT_DURATION_MS", 3_600_000),
      backoffMultiplier: intEnv("LOCKOUT_BACKOFF_MULTIPLIER", 2),
    },
    recovery: {
      wordCount,
      argon2Memory: intEnv("RECOVERY_ARGON2_MEMORY", 65536),
      argon2Iterations: intEnv("RECOVERY_ARGON2_ITERATIONS", 3),
      argon2Parallelism: intEnv("RECOVERY_ARGON2_PARALLELISM", 4),
      maxAttempts: intEnv("RECOVERY_MAX_ATTEMPTS", 3),
      mode,
    },
  };
}
