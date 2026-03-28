// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * @2fapi/protocol-spec — 2FApi Protocol Constants and Types
 *
 * This package defines the canonical protocol specification for 2FApi
 * Zero-Knowledge Proof authentication. It contains no implementation —
 * only constants, types, and interfaces shared between client and server.
 *
 * @license Apache-2.0
 * @see https://gitlab.continuum-identity.com/continuum-identity/2fapi
 */
export declare const PROTOCOL_VERSION = "1.0";
export declare const DOMAIN_SEPARATION_TAG = "2FApi-v1.0-Sigma";
export declare const ROTATION_DOMAIN_TAG = "2FApi-v1.0-Rotation";
export declare const TRANSCRIPT_DST = "2FApi-Sigma-Transcript-v1";
export declare const PROOF_BYTE_LENGTH = 96;
export declare const COMMITMENT_BYTE_LENGTH = 32;
export declare const SCALAR_BYTE_LENGTH = 32;
export declare const GROUP_ELEMENT_BYTE_LENGTH = 32;
export declare const NONCE_RANDOM_BYTE_LENGTH = 16;
export declare const NONCE_COUNTER_BYTE_LENGTH = 8;
export interface TranscriptFields {
    readonly tag: string;
    readonly generatorG: Uint8Array;
    readonly generatorH: Uint8Array;
    readonly commitment: Uint8Array;
    readonly announcement: Uint8Array;
    readonly clientIdentifier: string;
    readonly nonce: Uint8Array;
    readonly channelBinding: Uint8Array;
}
export interface ProofData {
    readonly announcement: Uint8Array;
    readonly responseS: Uint8Array;
    readonly responseR: Uint8Array;
}
export interface ChallengeData {
    readonly challengeId: string;
    readonly nonce: Uint8Array;
    readonly channelBinding: Uint8Array;
    readonly expiresAtMs: number;
}
export interface CommitmentData {
    readonly bytes: Uint8Array;
}
export interface VerificationResult {
    readonly success: boolean;
    readonly clientIdentifier?: string;
    readonly error?: string;
}
export interface TokenData {
    readonly bearerToken: string;
    readonly expiresAtMs: number;
}
export declare const ErrorCodes: {
    readonly CHALLENGE_REFUSED: "challenge_refused";
    readonly VERIFICATION_REFUSED: "verification_refused";
    readonly ACCESS_DENIED: "access_denied";
    readonly ISSUANCE_REFUSED: "issuance_refused";
    readonly RATE_LIMITED: "rate_limited";
    readonly UNSUPPORTED_VERSION: "unsupported_protocol_version";
};
export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
//# sourceMappingURL=index.d.ts.map
