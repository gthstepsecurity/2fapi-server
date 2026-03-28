// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { OprfKey } from "../../model/oprf-key.js";
/**
 * Server-side port: stores OPRF keys per (clientId, deviceId).
 */
export interface OprfKeyStore {
    save(key: OprfKey): Promise<void>;
    findByDevice(clientId: string, deviceId: string): Promise<OprfKey | null>;
    delete(clientId: string, deviceId: string): Promise<void>;
}
//# sourceMappingURL=oprf-key-store.d.ts.map
