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
// --- Protocol Constants ---
export const PROTOCOL_VERSION = "1.0";
export const DOMAIN_SEPARATION_TAG = "2FApi-v1.0-Sigma";
export const ROTATION_DOMAIN_TAG = "2FApi-v1.0-Rotation";
export const TRANSCRIPT_DST = "2FApi-Sigma-Transcript-v1";
// --- Byte Lengths ---
export const PROOF_BYTE_LENGTH = 96;
export const COMMITMENT_BYTE_LENGTH = 32;
export const SCALAR_BYTE_LENGTH = 32;
export const GROUP_ELEMENT_BYTE_LENGTH = 32;
export const NONCE_RANDOM_BYTE_LENGTH = 16;
export const NONCE_COUNTER_BYTE_LENGTH = 8;
// --- Protocol Error Codes ---
export const ErrorCodes = {
    CHALLENGE_REFUSED: "challenge_refused",
    VERIFICATION_REFUSED: "verification_refused",
    ACCESS_DENIED: "access_denied",
    ISSUANCE_REFUSED: "issuance_refused",
    RATE_LIMITED: "rate_limited",
    UNSUPPORTED_VERSION: "unsupported_protocol_version",
};
//# sourceMappingURL=index.js.map