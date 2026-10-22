// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authentication platform abstractions
//!
//! This module defines core authentication traits for the Kotton platform:
//! - `AuthenticationProvider`: User/identity authentication (login, session management)
//! - `RequestAuthProvider`: HTTP/API request signing and authorization
//!
//! These traits enable pluggable authentication backends for different use cases:
//! - Kotton-native PIN/JWT authentication
//! - OAuth/OIDC providers
//! - Cloud service authentication (AWS, Azure, etc.)
//! - Federated/peer node authentication

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// User/Identity Authentication
// ============================================================================

/// Result type for user authentication operations
pub type AuthResult<T> = Result<T, AuthError>;

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User not found: {0}")]
    NotFound(String),

    #[error("User already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid PIN")]
    InvalidPin,

    #[error("Invalid token or session")]
    InvalidToken,

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

/// User authentication result containing identity and optional token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    /// User identifier (username, email, DID, etc.)
    pub user_id: String,

    /// Optional session token (JWT, OAuth token, etc.)
    pub token: Option<String>,

    /// Optional additional claims/metadata
    pub metadata: HashMap<String, String>,
}

/// User authentication provider trait
///
/// Implement this trait to add support for different user authentication mechanisms:
/// - Kotton-native PIN/JWT
/// - OAuth/OIDC
/// - LDAP
/// - Federated identity
#[async_trait]
pub trait AuthenticationProvider: Send + Sync {
    /// Authenticate a user with credentials
    async fn authenticate(
        &self,
        user_id: &str,
        credentials: &Credentials,
    ) -> AuthResult<AuthenticationResult>;

    /// Create a new user identity
    async fn create_user(
        &self,
        user_id: &str,
        credentials: &Credentials,
    ) -> AuthResult<AuthenticationResult>;

    /// Verify a session token
    async fn verify_token(&self, token: &str) -> AuthResult<AuthenticationResult>;

    /// Refresh a session token (if supported)
    async fn refresh_token(&self, _token: &str) -> AuthResult<AuthenticationResult> {
        Err(AuthError::Other("Token refresh not supported".to_string()))
    }

    /// Revoke a session token (logout)
    async fn revoke_token(&self, _token: &str) -> AuthResult<()> {
        Err(AuthError::Other(
            "Token revocation not supported".to_string(),
        ))
    }

    /// Check if a user exists
    async fn user_exists(&self, user_id: &str) -> bool;

    /// Get provider name for logging/debugging
    fn provider_name(&self) -> &str;
}

/// Credentials for user authentication
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Password-based authentication
    Password(String),

    /// PIN-based authentication
    Pin(String),

    /// OAuth/OIDC token
    OAuthToken(String),

    /// API key
    ApiKey(String),

    /// Custom credentials with type and data
    Custom {
        credential_type: String,
        data: HashMap<String, String>,
    },
}

// ============================================================================
// HTTP/API Request Authentication
// ============================================================================

/// Result type for request auth operations
pub type RequestAuthResult<T> = Result<T, RequestAuthError>;

/// Request authentication errors
#[derive(Error, Debug)]
pub enum RequestAuthError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Other error: {0}")]
    Other(String),
}

/// Generic request abstraction for authentication
///
/// Works across different transports (HTTP, gRPC, WebSocket, etc.)
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// HTTP method or operation type
    pub method: String,

    /// Target URL or endpoint
    pub url: String,

    /// Request headers (will be modified by auth provider)
    pub headers: HashMap<String, String>,

    /// Optional request body
    pub body: Option<Vec<u8>>,
}

impl AuthRequest {
    /// Create a new request
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Add body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Get header value
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }
}

/// Request authentication provider trait
///
/// Implement this trait to add support for different request signing mechanisms:
/// - AWS SigV4
/// - Azure SAS
/// - Bearer tokens
/// - Custom signing schemes
#[async_trait]
pub trait RequestAuthProvider: Send + Sync {
    /// Authenticate a request by adding necessary headers/signatures
    async fn authenticate_request(&self, request: &mut AuthRequest) -> RequestAuthResult<()>;

    /// Get provider name for logging/debugging
    fn provider_name(&self) -> &str;

    /// Optional: Get credentials info for display/config purposes
    fn credentials_info(&self) -> Option<String> {
        None
    }
}
