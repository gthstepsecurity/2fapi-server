// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const MIGRATIONS_DIR = resolve(
  import.meta.dirname ?? __dirname,
  "../../../infrastructure/postgresql/migrations",
);

describe("SQL migrations", () => {
  describe("007 — add suspended status to clients CHECK constraint", () => {
    const migrationPath = resolve(MIGRATIONS_DIR, "007_add_suspended_status.sql");

    it("migration file exists", () => {
      expect(existsSync(migrationPath)).toBe(true);
    });

    it("drops the old CHECK constraint", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("DROP CONSTRAINT");
    });

    it("adds a CHECK constraint that includes suspended", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("'active'");
      expect(sql).toContain("'suspended'");
      expect(sql).toContain("'revoked'");
      expect(sql).toContain("ADD CONSTRAINT");
      expect(sql).toContain("CHECK");
    });
  });

  describe("008 — create recovery_hashes table", () => {
    const migrationPath = resolve(MIGRATIONS_DIR, "008_create_recovery_hashes.sql");

    it("migration file exists", () => {
      expect(existsSync(migrationPath)).toBe(true);
    });

    it("creates recovery_hashes table with required columns", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("CREATE TABLE");
      expect(sql).toContain("recovery_hashes");
      expect(sql).toContain("client_identifier");
      expect(sql).toContain("hash");
      expect(sql).toContain("salt");
      expect(sql).toContain("failed_attempts");
      expect(sql).toContain("created_at");
      expect(sql).toContain("updated_at");
    });

    it("uses client_identifier as primary key", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("PRIMARY KEY");
    });

    it("has a foreign key to clients table", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("FOREIGN KEY");
      expect(sql).toContain("clients");
    });
  });

  describe("009 — create ip_bindings table", () => {
    const migrationPath = resolve(MIGRATIONS_DIR, "009_create_ip_bindings.sql");

    it("migration file exists", () => {
      expect(existsSync(migrationPath)).toBe(true);
    });

    it("creates ip_bindings table with required columns", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("CREATE TABLE");
      expect(sql).toContain("ip_bindings");
      expect(sql).toContain("client_identifier");
      expect(sql).toContain("source_ip");
      expect(sql).toContain("bound_at_ms");
    });

    it("creates index on client_identifier", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("CREATE INDEX");
      expect(sql).toContain("idx_ip_bindings_client");
    });

    it("has a foreign key to clients table", () => {
      const sql = readFileSync(migrationPath, "utf-8");
      expect(sql).toContain("FOREIGN KEY");
      expect(sql).toContain("clients");
    });
  });
});
