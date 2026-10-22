// SPDX-License-Identifier: AGPL-3.0-or-later
use thiserror::Error;

/// PIN/passphrase strength validator
pub struct PinValidator {
    min_length: usize,
    max_length: usize,
    require_numeric: bool,
}

impl Default for PinValidator {
    fn default() -> Self {
        Self {
            min_length: 6,
            max_length: 16,
            require_numeric: true,
        }
    }
}

impl PinValidator {
    /// Create validator with default settings (6-16 digit PIN)
    pub fn new() -> Self {
        Self::default()
    }

    /// Create validator that allows alphanumeric passphrases
    pub fn passphrase() -> Self {
        Self {
            min_length: 8,
            max_length: 64,
            require_numeric: false,
        }
    }

    /// Validate PIN/passphrase strength
    pub fn validate(&self, pin: &str) -> Result<(), PinError> {
        if pin.is_empty() {
            return Err(PinError::Empty);
        }

        if pin.len() < self.min_length {
            return Err(PinError::TooShort {
                min: self.min_length,
            });
        }

        if pin.len() > self.max_length {
            return Err(PinError::TooLong {
                max: self.max_length,
            });
        }

        if self.require_numeric && !pin.chars().all(|c| c.is_numeric()) {
            return Err(PinError::NotNumeric);
        }

        // Check for common weak PINs
        if is_weak_pin(pin) {
            return Err(PinError::TooWeak);
        }

        Ok(())
    }
}

/// Check if PIN is on the weak PIN list
fn is_weak_pin(pin: &str) -> bool {
    const WEAK_PINS: &[&str] = &[
        // Repeating digits
        "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888",
        "999999", // Sequential
        "123456", "654321", "123123", "012345", "234567", "345678", "456789", "567890",
        // Common patterns
        "112233", "121212", "123321", "696969",
    ];

    WEAK_PINS.contains(&pin)
}

#[derive(Debug, Error)]
pub enum PinError {
    #[error("PIN cannot be empty")]
    Empty,

    #[error("PIN too short (minimum {min} characters)")]
    TooShort { min: usize },

    #[error("PIN too long (maximum {max} characters)")]
    TooLong { max: usize },

    #[error("PIN must be numeric (digits only)")]
    NotNumeric,

    #[error("PIN is too weak (avoid common patterns like 111111, 123456, etc.)")]
    TooWeak,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_pin() {
        let validator = PinValidator::default();
        assert!(validator.validate("147258").is_ok());
        assert!(validator.validate("9876543210").is_ok());
    }

    #[test]
    fn test_weak_pins_rejected() {
        let validator = PinValidator::default();
        assert!(validator.validate("111111").is_err());
        assert!(validator.validate("123456").is_err());
        assert!(validator.validate("000000").is_err());
        assert!(validator.validate("654321").is_err());
    }

    #[test]
    fn test_too_short() {
        let validator = PinValidator::default();
        let result = validator.validate("123");
        assert!(matches!(result, Err(PinError::TooShort { min: 6 })));
    }

    #[test]
    fn test_too_long() {
        let validator = PinValidator::default();
        let result = validator.validate("12345678901234567890");
        assert!(matches!(result, Err(PinError::TooLong { max: 16 })));
    }

    #[test]
    fn test_not_numeric() {
        let validator = PinValidator::default();
        assert!(matches!(
            validator.validate("abc123"),
            Err(PinError::NotNumeric)
        ));
    }

    #[test]
    fn test_passphrase_mode() {
        let validator = PinValidator::passphrase();
        assert!(validator.validate("MySecurePass123").is_ok());
        assert!(validator.validate("correct horse battery staple").is_ok());
    }

    #[test]
    fn test_empty_pin() {
        let validator = PinValidator::default();
        assert!(matches!(validator.validate(""), Err(PinError::Empty)));
    }
}
