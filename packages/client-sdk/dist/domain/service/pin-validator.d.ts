// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result } from "../model/result.js";
/**
 * Domain service for 6-digit PIN validation.
 * Pure logic — no infrastructure dependencies.
 */
export declare class PinValidator {
    /**
     * Validate a PIN: exactly 6 digits, not all identical.
     * Sequential/weak PINs are accepted with a warning (use isWeak() to check).
     */
    validate(raw: string): Result<string, string>;
    /**
     * Check if a PIN is weak (sequential or common).
     * Returns true for PINs that should show a warning.
     */
    isWeak(pin: string): boolean;
    /**
     * Filter non-numeric characters from raw input.
     * Used for real-time input filtering in PIN fields.
     */
    filterNumeric(raw: string): string;
}
//# sourceMappingURL=pin-validator.d.ts.map
