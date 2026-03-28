/**
 * Value object: one share of a 2-of-2 additive secret sharing.
 *
 * The full Pedersen secret (s, r) is split: s = s1 + s2, r = r1 + r2.
 * This share holds (s_i, r_i) — half the secret.
 * The full secret NEVER exists in cleartext on any single machine.
 */
export class SecretShare {
    shareS;
    shareR;
    party;
    constructor(shareS, shareR, party) {
        this.shareS = shareS;
        this.shareR = shareR;
        this.party = party;
    }
    static create(shareS, shareR, party) {
        if (shareS.length !== 32 || shareR.length !== 32) {
            throw new Error("Share scalars must be 32 bytes");
        }
        return new SecretShare(shareS, shareR, party);
    }
    /**
     * Compute a partial Sigma response: z_s_i = k_s + c · s_i (client)
     * or z_s_i = c · s_i (server, no nonce).
     *
     * This is a LINEAR operation — the core of why secret sharing works
     * for Sigma proofs without ever reconstructing the secret.
     */
    computePartialResponse(challenge, nonce_s, nonce_r) {
        // The actual scalar arithmetic is done in WASM/NAPI.
        // This model represents the STRUCTURE, not the computation.
        return {
            z_s_partial: this.shareS, // placeholder — real impl in WASM
            z_r_partial: this.shareR,
            party: this.party,
        };
    }
}
//# sourceMappingURL=secret-share.js.map