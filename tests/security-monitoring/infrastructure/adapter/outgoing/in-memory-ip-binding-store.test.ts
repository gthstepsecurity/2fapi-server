// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryIpBindingStore } from "../../../../../src/security-monitoring/infrastructure/adapter/outgoing/in-memory-ip-binding-store.js";
import { IpBinding } from "../../../../../src/security-monitoring/domain/model/ip-binding.js";

describe("InMemoryIpBindingStore", () => {
  let store: InMemoryIpBindingStore;

  beforeEach(() => {
    store = new InMemoryIpBindingStore();
  });

  it("saves and retrieves bindings by client identifier", async () => {
    const binding = IpBinding.create("alice", "10.0.0.1", 1000);
    await store.save(binding);

    const results = await store.findByClientIdentifier("alice");
    expect(results).toHaveLength(1);
    expect(results[0].sourceIp).toBe("10.0.0.1");
  });

  it("returns empty array for unknown client", async () => {
    const results = await store.findByClientIdentifier("unknown");
    expect(results).toHaveLength(0);
  });

  it("returns latest binding for client", async () => {
    await store.save(IpBinding.create("alice", "10.0.0.1", 1000));
    await store.save(IpBinding.create("alice", "10.0.0.2", 2000));

    const latest = await store.findLatestByClientIdentifier("alice");
    expect(latest).not.toBeNull();
    expect(latest!.sourceIp).toBe("10.0.0.2");
  });

  it("returns null for latest when no bindings exist", async () => {
    const latest = await store.findLatestByClientIdentifier("unknown");
    expect(latest).toBeNull();
  });

  it("isolates bindings between clients", async () => {
    await store.save(IpBinding.create("alice", "10.0.0.1", 1000));
    await store.save(IpBinding.create("bob", "10.0.0.2", 2000));

    const aliceBindings = await store.findByClientIdentifier("alice");
    const bobBindings = await store.findByClientIdentifier("bob");

    expect(aliceBindings).toHaveLength(1);
    expect(bobBindings).toHaveLength(1);
    expect(aliceBindings[0].sourceIp).toBe("10.0.0.1");
    expect(bobBindings[0].sourceIp).toBe("10.0.0.2");
  });
});
