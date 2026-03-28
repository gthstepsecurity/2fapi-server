// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { Client } from "../../model/client.js";

export interface ClientRepository {
  save(client: Client): Promise<void>;
  update(client: Client): Promise<void>;
  // TODO: Consider hashing clientIdentifier before storage to prevent enumeration at the repository level
  findByIdentifier(identifier: string): Promise<Client | null>;
  existsByIdentifier(identifier: string): Promise<boolean>;
}
