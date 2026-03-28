// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { IpBinding } from "../../model/ip-binding.js";

/**
 * Driven port for storing and retrieving IP bindings per client.
 */
export interface IpBindingStore {
  save(binding: IpBinding): Promise<void>;
  findByClientIdentifier(clientIdentifier: string): Promise<readonly IpBinding[]>;
  findLatestByClientIdentifier(clientIdentifier: string): Promise<IpBinding | null>;
}
