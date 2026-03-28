// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Helper to check if integration test infrastructure services are running.
 *
 * Usage:
 *   const available = await checkDockerServices();
 *   describe.skipIf(!available.postgres)("PgAdapter [integration]", () => { ... });
 *
 * Prerequisites:
 *   docker compose up -d
 */

export interface ServiceAvailability {
  readonly postgres: boolean;
  readonly redis: boolean;
}

/**
 * Default connection settings for development Docker services.
 */
export const PG_CONFIG = {
  host: process.env.TWOFAPI_DB_HOST ?? "127.0.0.1",
  port: parseInt(process.env.TWOFAPI_DB_PORT ?? "5434", 10),
  database: process.env.TWOFAPI_DB_NAME ?? "twofapi",
  user: process.env.TWOFAPI_DB_USER ?? "twofapi",
  password: process.env.TWOFAPI_DB_PASSWORD ?? "2FApi-dev-password-2026",
} as const;

export const REDIS_CONFIG = {
  host: process.env.TWOFAPI_REDIS_HOST ?? "127.0.0.1",
  port: parseInt(process.env.TWOFAPI_REDIS_PORT ?? "6379", 10),
  password: process.env.TWOFAPI_REDIS_PASSWORD ?? "2FApi-redis-dev-2026",
} as const;

/**
 * Checks if PostgreSQL and Redis are available.
 * Uses dynamic imports to avoid requiring pg/ioredis in unit test runs.
 */
export async function checkDockerServices(): Promise<ServiceAvailability> {
  const result: ServiceAvailability = {
    postgres: await checkPostgres(),
    redis: await checkRedis(),
  };
  return result;
}

async function checkPostgres(): Promise<boolean> {
  try {
    const pg = await import("pg");
    const pool = new pg.Pool(PG_CONFIG);
    const client = await pool.connect();
    client.release();
    await pool.end();
    return true;
  } catch {
    return false;
  }
}

async function checkRedis(): Promise<boolean> {
  try {
    const Redis = (await import("ioredis")).default;
    const redis = new Redis(REDIS_CONFIG);
    await redis.ping();
    await redis.quit();
    return true;
  } catch {
    return false;
  }
}

/**
 * Creates a PostgreSQL pool for integration tests.
 * Returns null if pg is not available.
 */
export async function createTestPool(): Promise<any | null> {
  try {
    const pg = await import("pg");
    return new pg.Pool(PG_CONFIG);
  } catch {
    return null;
  }
}

/**
 * Creates a Redis client for integration tests.
 * Returns null if ioredis is not available.
 */
export async function createTestRedis(): Promise<any | null> {
  try {
    const Redis = (await import("ioredis")).default;
    return new Redis(REDIS_CONFIG);
  } catch {
    return null;
  }
}

/**
 * Truncates all tables used in integration tests.
 * Call in beforeEach to ensure test isolation.
 */
export async function truncateAllTables(pool: any): Promise<void> {
  await pool.query(`
    TRUNCATE TABLE
      recovery_hashes,
      ip_bindings,
      anomaly_baselines,
      failed_attempts,
      audit_log,
      challenges,
      clients
    CASCADE
  `);
}

/**
 * Flushes all keys in the current Redis database.
 * Call in beforeEach to ensure test isolation.
 */
export async function flushRedis(redis: any): Promise<void> {
  await redis.flushdb();
}
