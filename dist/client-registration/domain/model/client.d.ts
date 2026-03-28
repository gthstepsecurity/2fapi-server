import type { ClientId } from "./client-id.js";
import type { ClientStatus } from "./client-status.js";
import type { Commitment } from "./commitment.js";
export declare class Client {
    readonly id: ClientId;
    readonly identifier: string;
    readonly commitment: Commitment;
    readonly status: ClientStatus;
    private constructor();
    static register(id: ClientId, identifier: string, commitment: Commitment): Client;
}
//# sourceMappingURL=client.d.ts.map