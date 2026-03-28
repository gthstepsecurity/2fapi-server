import { ok, err } from "../model/result.js";
const PIN_LENGTH = 6;
const WEAK_PINS = new Set(["123456", "654321", "000000"]);
/**
 * Domain service for 6-digit PIN validation.
 * Pure logic — no infrastructure dependencies.
 */
export class PinValidator {
    /**
     * Validate a PIN: exactly 6 digits, not all identical.
     * Sequential/weak PINs are accepted with a warning (use isWeak() to check).
     */
    validate(raw) {
        if (raw.length !== PIN_LENGTH) {
            return err("PIN must be 6 digits");
        }
        if (!/^\d{6}$/.test(raw)) {
            return err("PIN must contain only digits");
        }
        // Reject all-same digits (111111, 222222, etc.)
        if (raw.split("").every(c => c === raw[0])) {
            return err("PIN must not be all the same digit");
        }
        return ok(raw);
    }
    /**
     * Check if a PIN is weak (sequential or common).
     * Returns true for PINs that should show a warning.
     */
    isWeak(pin) {
        return WEAK_PINS.has(pin);
    }
    /**
     * Filter non-numeric characters from raw input.
     * Used for real-time input filtering in PIN fields.
     */
    filterNumeric(raw) {
        return raw.replace(/\D/g, "");
    }
}
//# sourceMappingURL=pin-validator.js.map