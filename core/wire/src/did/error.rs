// SPDX-License-Identifier: AGPL-3.0-or-later
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DidError {
    #[error("Invalid DID format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    #[error("Invalid multibase encoding: {0}")]
    InvalidMultibase(String),

    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, DidError>;
