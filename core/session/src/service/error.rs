// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authentication service error types

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User identity not found: {0}")]
    NotFound(String),

    #[error("User identity already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid PIN")]
    InvalidPin,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Other error: {0}")]
    Other(String),
}

// Convert from platform auth errors
impl From<kotton_sys::session::AuthError> for AuthError {
    fn from(e: kotton_sys::session::AuthError) -> Self {
        use kotton_sys::session::AuthError as PlatformAuthError;
        match e {
            PlatformAuthError::NotFound(s) => AuthError::NotFound(s),
            PlatformAuthError::AlreadyExists(s) => AuthError::AlreadyExists(s),
            PlatformAuthError::InvalidCredentials => AuthError::InvalidCredentials,
            PlatformAuthError::InvalidPin => AuthError::InvalidPin,
            PlatformAuthError::InvalidToken => AuthError::InvalidToken,
            PlatformAuthError::CryptoError(s) => AuthError::CryptoError(s),
            PlatformAuthError::StorageError(s) => AuthError::StorageError(s),
            PlatformAuthError::SerializationError(s) => AuthError::SerializationError(s),
            PlatformAuthError::InvalidData(s) => AuthError::InvalidData(s),
            PlatformAuthError::AuthenticationFailed(s) => AuthError::AuthenticationFailed(s),
            PlatformAuthError::Other(s) => AuthError::Other(s),
        }
    }
}

impl From<super::PinError> for AuthError {
    fn from(e: super::PinError) -> Self {
        AuthError::InvalidData(e.to_string())
    }
}
