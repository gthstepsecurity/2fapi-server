// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! Brute-force protection domain logic.
//!
//! Tracks failed authentication attempts per device/user and triggers
//! a wipe + server-side revocation when the threshold is reached.

/// Default maximum failed attempts before wipe.
pub const DEFAULT_MAX_ATTEMPTS: i32 = 5;

/// Minimum configurable threshold (prevents accidental lockout).
pub const MIN_THRESHOLD: i32 = 3;

/// Result of checking the brute-force counter.
#[derive(Debug, Clone, PartialEq)]
pub enum BruteForceAction {
    /// Allow the attempt. Includes the current attempt count.
    Allow { attempts: i32, max: i32 },
    /// Warn the user — one attempt remaining.
    Warn { attempts: i32, max: i32 },
    /// Wipe: threshold reached. Device commitment must be revoked.
    Wipe { attempts: i32, max: i32 },
}

/// Determines the action based on the current attempt count.
///
/// Called AFTER a failed authentication attempt (counter already incremented).
pub fn check_attempts(current_attempts: i32, max_attempts: i32) -> BruteForceAction {
    let max = max_attempts.max(MIN_THRESHOLD);

    if current_attempts >= max {
        BruteForceAction::Wipe {
            attempts: current_attempts,
            max,
        }
    } else if current_attempts == max - 1 {
        BruteForceAction::Warn {
            attempts: current_attempts,
            max,
        }
    } else {
        BruteForceAction::Allow {
            attempts: current_attempts,
            max,
        }
    }
}

/// Validates a configurable threshold.
pub fn validate_threshold(threshold: i32) -> Result<i32, &'static str> {
    if threshold == 0 {
        Ok(0) // 0 means disabled
    } else if threshold < MIN_THRESHOLD {
        Err("threshold must be 0 (disabled) or at least 3")
    } else {
        Ok(threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_when_below_threshold() {
        assert_eq!(
            check_attempts(1, 5),
            BruteForceAction::Allow { attempts: 1, max: 5 }
        );
    }

    #[test]
    fn allow_at_3_of_5() {
        assert_eq!(
            check_attempts(3, 5),
            BruteForceAction::Allow { attempts: 3, max: 5 }
        );
    }

    #[test]
    fn warn_at_4_of_5() {
        assert_eq!(
            check_attempts(4, 5),
            BruteForceAction::Warn { attempts: 4, max: 5 }
        );
    }

    #[test]
    fn wipe_at_5_of_5() {
        assert_eq!(
            check_attempts(5, 5),
            BruteForceAction::Wipe { attempts: 5, max: 5 }
        );
    }

    #[test]
    fn wipe_at_6_of_5() {
        assert_eq!(
            check_attempts(6, 5),
            BruteForceAction::Wipe { attempts: 6, max: 5 }
        );
    }

    #[test]
    fn threshold_clamped_to_minimum() {
        // If admin sets threshold to 1, it's clamped to 3
        assert_eq!(
            check_attempts(2, 1),
            BruteForceAction::Warn { attempts: 2, max: 3 }
        );
    }

    #[test]
    fn threshold_3_warns_at_2() {
        assert_eq!(
            check_attempts(2, 3),
            BruteForceAction::Warn { attempts: 2, max: 3 }
        );
    }

    #[test]
    fn validate_threshold_accepts_valid() {
        assert_eq!(validate_threshold(5), Ok(5));
        assert_eq!(validate_threshold(3), Ok(3));
        assert_eq!(validate_threshold(100), Ok(100));
    }

    #[test]
    fn validate_threshold_accepts_disabled() {
        assert_eq!(validate_threshold(0), Ok(0));
    }

    #[test]
    fn validate_threshold_rejects_too_low() {
        assert!(validate_threshold(1).is_err());
        assert!(validate_threshold(2).is_err());
    }
}
