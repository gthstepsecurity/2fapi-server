import type { Client } from "../../model/client.js";
export interface ClientRepository {
    save(client: Client): Promise<void>;
    findByIdentifier(identifier: string): Promise<Client | null>;
    existsByIdentifier(identifier: string): Promise<boolean>;
}
//# sourceMappingURL=client-repository.d.ts.map