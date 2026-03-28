export declare class ClientId {
    private readonly bytes;
    private constructor();
    static fromBytes(bytes: Uint8Array): ClientId;
    toBytes(): Uint8Array;
    equals(other: ClientId): boolean;
    toString(): string;
}
//# sourceMappingURL=client-id.d.ts.map