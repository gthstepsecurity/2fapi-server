import type { ClientRepository } from "../../../domain/port/outgoing/client-repository.js";
import type { Client } from "../../../domain/model/client.js";
export declare class InMemoryClientRepository implements ClientRepository {
    private readonly clients;
    save(client: Client): Promise<void>;
    findByIdentifier(identifier: string): Promise<Client | null>;
    existsByIdentifier(identifier: string): Promise<boolean>;
}
//# sourceMappingURL=in-memory-client-repository.d.ts.map