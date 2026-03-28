export class InMemoryClientRepository {
    clients = new Map();
    async save(client) {
        if (this.clients.has(client.identifier)) {
            throw new Error("Optimistic concurrency conflict");
        }
        this.clients.set(client.identifier, client);
    }
    async findByIdentifier(identifier) {
        return this.clients.get(identifier) ?? null;
    }
    async existsByIdentifier(identifier) {
        return this.clients.has(identifier);
    }
}
//# sourceMappingURL=in-memory-client-repository.js.map