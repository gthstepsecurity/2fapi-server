export declare class Commitment {
    private readonly bytes;
    private constructor();
    static fromBytes(bytes: Uint8Array): Commitment;
    toBytes(): Uint8Array;
    /** Byte-exact comparison. NOTE: This is NOT constant-time.
     *  Do not use in cryptographic verification paths. */
    equals(other: Commitment): boolean;
}
//# sourceMappingURL=commitment.d.ts.map