export class Client {
    id;
    identifier;
    commitment;
    status;
    constructor(id, identifier, commitment, status) {
        this.id = id;
        this.identifier = identifier;
        this.commitment = commitment;
        this.status = status;
    }
    static register(id, identifier, commitment) {
        if (!identifier || identifier.trim().length === 0) {
            throw new Error("Client identifier must not be empty");
        }
        return new Client(id, identifier, commitment, "active");
    }
}
//# sourceMappingURL=client.js.map